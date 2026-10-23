//! Exercise the shipped executable and actual newline-delimited MCP transport.
use serde_json::{json, Value};
use std::{
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc,
    time::Duration,
};

#[cfg(all(windows, target_arch = "x86_64"))]
#[path = "../../../tests/support/debug_fixture.rs"]
mod debug_fixture;
struct Client {
    child: Child,
    input: ChildStdin,
    replies: mpsc::Receiver<Value>,
    id: u64,
}
impl Client {
    fn start(root: &Path, writes: bool) -> Self {
        Self::start_options(root, writes, &[])
    }
    fn start_options(root: &Path, writes: bool, extra: &[String]) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ura-mcp"));
        command.args(["--allow", root.to_str().unwrap(), "--log", "off"]);
        if writes {
            command.arg("--enable-writes");
        }
        command.args(extra);
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = child.stdout.take().unwrap();
        let (sender, replies) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                let line = line.expect("MCP stdout read");
                let value = serde_json::from_str(&line).expect("stdout must contain only MCP JSON");
                if sender.send(value).is_err() {
                    break;
                }
            }
        });
        let mut client = Self {
            child,
            input,
            replies,
            id: 0,
        };
        let result = client.request("initialize", json!({"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"ura-regression","version":"1"}}));
        assert!(
            result["result"]["capabilities"]["tools"].is_object(),
            "{result}"
        );
        assert_eq!(
            result["result"]["serverInfo"]["name"], "ura-mcp",
            "{result}"
        );
        assert_eq!(
            result["result"]["serverInfo"]["version"],
            env!("CARGO_PKG_VERSION"),
            "{result}"
        );
        client.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
        client
    }
    fn send(&mut self, value: Value) {
        writeln!(self.input, "{value}").unwrap();
        self.input.flush().unwrap();
    }
    fn request(&mut self, method: &str, params: Value) -> Value {
        self.id += 1;
        self.send(json!({"jsonrpc":"2.0","id":self.id,"method":method,"params":params}));
        loop {
            let value = self
                .replies
                .recv_timeout(Duration::from_secs(15))
                .expect("MCP response within timeout");
            if value["id"] == self.id {
                return value;
            }
        }
    }
    fn tool_result(&mut self, name: &str, args: Value) -> Value {
        let value = self.request("tools/call", json!({"name":name,"arguments":args}));
        assert!(value["error"].is_null(), "{value}");
        value["result"].clone()
    }
    fn tool(&mut self, name: &str, args: Value) -> Value {
        let result = self.tool_result(name, args);
        assert_ne!(result["isError"], true, "{result}");
        let data = result["structuredContent"].clone();
        assert_eq!(data["schemaVersion"], 1, "{result}");
        data
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/ura64.exe")
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn stdio_debugger_launch_step_and_separate_permission_boundary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let target = debug_fixture::fixture();
    let mut denied = Client::start(&root, true);
    let result = denied.tool_result("ura_debug_launch", json!({"executable":target}));
    assert_eq!(
        result["isError"], true,
        "ordinary writes must not enable execution"
    );
    let mut client = Client::start_options(
        &root,
        false,
        &[
            "--enable-debug-launch".into(),
            "--enable-debug-capture".into(),
            "--debug-target".into(),
            target.display().to_string(),
        ],
    );
    let launched = client.tool("ura_debug_launch", json!({"executable":target}))["result"].clone();
    let session = launched["session"].clone();
    assert!(session.is_string(), "{launched}");
    let wait = |client: &mut Client, state: &str| {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let status =
                client.tool("ura_debug_status", json!({"session":session}))["result"].clone();
            if status["state"] == state {
                break status;
            }
            assert!(std::time::Instant::now() < deadline, "{status}");
            std::thread::sleep(Duration::from_millis(15));
        }
    };
    let paused = wait(&mut client, "paused");
    let memory = client.tool(
        "ura_debug_read_memory",
        json!({"session":session,"address":paused["registers"]["values"]["rip"],"length":16}),
    );
    assert_eq!(memory["result"]["read"], 16);
    client.tool("ura_debug_step", json!({"session":session}));
    let stepped = wait(&mut client, "paused");
    assert_eq!(stepped["reason"], "singleStep");
    let caps = client.tool("ura_debug_capabilities", json!({}));
    assert_eq!(caps["result"]["hardwareSlotsPerThread"], 4);
    let capture=client.tool("ura_debug_snapshot",json!({"session":session,"action":"capture","address":stepped["registers"]["values"]["rip"],"length":32}));
    assert_eq!(capture["result"]["captured"], 32);
    let export=client.tool_result("ura_debug_snapshot",json!({"session":session,"action":"export","id":capture["result"]["id"],"destination":root.join("target/denied-mcp-capture.json")}));
    assert_eq!(export["isError"], true);
    client.tool(
        "ura_debug_trace",
        json!({"session":session,"action":"start","config":{"mode":"instructions","maxSteps":4}}),
    );
    assert_eq!(wait(&mut client, "paused")["trace"]["steps"], 4);
    assert!(client.tool(
        "ura_debug_trace",
        json!({"session":session,"action":"read","limit":128})
    )["result"]["events"]
        .is_array());
    client.tool("ura_debug_symbols",json!({"session":session,"action":"load","base":paused["modules"][0]["base"],"pdb":target.with_extension("pdb")}));
    let binary = ura_core::analyze_path(&target).unwrap();
    let marker = ura_core::parse_address(paused["modules"][0]["base"].as_str().unwrap()).unwrap()
        + ura_core::parse_address(
            &binary
                .analysis()
                .export_view_list()
                .iter()
                .find(|e| e.name == "ura_marker")
                .unwrap()
                .address,
        )
        .unwrap()
        - ura_core::parse_address(&binary.view().image_base).unwrap();
    client.tool("ura_debug_configure_breakpoint",json!({"session":session,"address":ura_core::format_address(marker),"kind":"hardwareExecute","condition":"ecx == 2"}));
    client.tool("ura_debug_continue", json!({"session":session}));
    let hit = wait(&mut client, "paused");
    assert_eq!(hit["reason"], "hardwareBreakpoint");
    assert_eq!(hit["registers"]["values"]["rcx"], "0x2");
    assert_eq!(client.tool("ura_debug_symbols",json!({"session":session,"action":"lookup","address":ura_core::format_address(marker+1)}))["result"]["found"],true);
    let denied = client.tool_result("ura_debug_attach", json!({"pid":4,"executable":target}));
    assert_eq!(denied["isError"], true);
    client.tool("ura_debug_terminate", json!({"session":session}));
    wait(&mut client, "exited");
}

#[test]
fn stdio_patching_preview_apply_history_export_and_permissions() {
    let directory = tempfile::tempdir().unwrap();
    let sample = directory.path().join("sample.exe");
    std::fs::copy(fixture(), &sample).unwrap();
    let original = std::fs::read(&sample).unwrap();
    let project = directory.path().join("patches.ura");
    let mut writer = Client::start(directory.path(), true);
    let handle = writer.tool("ura_open_binary", json!({"binary":sample}))["handle"].clone();
    writer.tool(
        "ura_save_project",
        json!({"handle":handle,"project":project}),
    );
    writer.tool("ura_analyze", json!({"handle":handle}));
    let preview = writer.tool(
        "ura_preview_instruction_patch",
        json!({"handle":handle,"space":"va","address":"140001020","budget":1,"assembly":"ret"}),
    );
    assert_eq!(preview["patch"]["edits"][0]["after"], json!([195]));
    let changed = writer.tool(
        "ura_apply_patch",
        json!({"handle":handle,"project":project,"preview":preview}),
    );
    assert_eq!(changed["analysisCurrent"], false);
    let current = writer.tool(
        "ura_read_effective_bytes",
        json!({"handle":handle,"space":"offset","address":"220","length":1}),
    );
    assert_eq!(current["original"], json!([85]));
    assert_eq!(current["current"], json!([195]));
    let stale = writer.tool_result(
        "ura_apply_patch",
        json!({"handle":handle,"project":project,"preview":preview}),
    );
    assert_eq!(stale["isError"], true);
    writer.tool(
        "ura_patch_history",
        json!({"handle":handle,"project":project,"action":"undo"}),
    );
    writer.tool(
        "ura_patch_history",
        json!({"handle":handle,"project":project,"action":"redo"}),
    );
    writer.tool("ura_analyze", json!({"handle":handle}));
    let decompiled = writer.tool(
        "ura_decompile_function",
        json!({"handle":handle,"function":"140001020"}),
    );
    assert!(decompiled["total"].as_u64().unwrap() < 27);
    let out = directory.path().join("patched.exe");
    let exported = writer.tool(
        "ura_export_patched_binary",
        json!({"handle":handle,"destination":out}),
    );
    let bytes = std::fs::read(&out).unwrap();
    assert_eq!(exported["sha256"], ura_core::sha256_hex(&bytes));
    assert_eq!(&bytes[..0x220], &original[..0x220]);
    assert_eq!(&bytes[0x221..], &original[0x221..]);
    let manifest = directory.path().join("patches.json");
    writer.tool(
        "ura_export_patched_binary",
        json!({"handle":handle,"destination":manifest,"manifest":true}),
    );
    assert!(
        serde_json::from_slice::<Value>(&std::fs::read(manifest).unwrap()).unwrap()["transactions"]
            .is_array()
    );
    let mut reader = Client::start(directory.path(), false);
    let readonly = reader.tool(
        "ura_open_binary",
        json!({"binary":sample,"project":project}),
    )["handle"]
        .clone();
    reader.tool("ura_list_patches", json!({"handle":readonly}));
    let preview=reader.tool("ura_preview_byte_patch",json!({"handle":readonly,"space":"offset","address":"220","expected":"C3","replacement":"90"}));
    let denied = reader.tool_result(
        "ura_apply_patch",
        json!({"handle":readonly,"project":project,"preview":preview}),
    );
    assert_eq!(
        denied["structuredContent"]["error"]["code"],
        "write_disabled"
    );
    assert_eq!(std::fs::read(sample).unwrap(), original);
}

#[test]
fn stdio_queries_errors_and_read_only_permissions() {
    let directory = tempfile::tempdir().unwrap();
    let sample = directory.path().join("sample.exe");
    std::fs::copy(fixture(), &sample).unwrap();
    let mut client = Client::start(directory.path(), false);
    let tools = client.request("tools/list", json!({}));
    let listed = tools["result"]["tools"].as_array().unwrap();
    assert_eq!(listed.len(), 67);
    for tool in listed {
        let expected = !matches!(
            tool["name"].as_str().unwrap(),
            "ura_rename_function"
                | "ura_add_comment"
                | "ura_save_project"
                | "ura_export_analysis"
                | "ura_export_decompiled_function"
                | "ura_close_binary"
                | "ura_set_function_signature"
                | "ura_set_variable_type"
                | "ura_set_type_library"
                | "ura_apply_patch"
                | "ura_patch_history"
                | "ura_export_patched_binary"
                | "ura_debug_launch"
                | "ura_debug_attach"
                | "ura_debug_continue"
                | "ura_debug_pause"
                | "ura_debug_step"
                | "ura_debug_detach"
                | "ura_debug_terminate"
                | "ura_debug_breakpoints"
                | "ura_debug_configure_breakpoint"
                | "ura_debug_set_condition"
                | "ura_debug_step_out"
                | "ura_debug_run_to"
                | "ura_debug_trace"
                | "ura_debug_snapshot"
                | "ura_debug_symbols"
                | "ura_emulation"
                | "ura_memory_image"
        );
        assert_eq!(tool["annotations"]["readOnlyHint"], expected, "{tool}");
    }
    let data = client.tool("ura_open_binary", json!({"binary":sample}));
    let handle = data["handle"].as_str().unwrap();
    assert_eq!(data["info"]["format"], "PE");
    client.tool("ura_get_binary_info", json!({"handle":handle}));
    client.tool("ura_analyze", json!({"handle":handle}));
    let mut shared = ura_service::Service::new(ura_service::PathPolicy::allow_all(), false);
    let shared_handle = shared.open_binary(&sample, None).unwrap().handle;
    shared.analyze(&shared_handle, &Default::default()).unwrap();
    let source = client.tool(
        "ura_decompile_function",
        json!({"handle":handle,"function":"140001020","ast":true,"limit":200}),
    );
    assert_eq!(
        source,
        serde_json::to_value(
            shared
                .decompile(&shared_handle, "140001020", 0, 200, true)
                .unwrap()
        )
        .unwrap()
    );
    let denied=client.request("tools/call",json!({"name":"ura_export_decompiled_function","arguments":{"handle":handle,"function":"140001020","destination":directory.path().join("denied.c")}}));
    assert_eq!(denied["result"]["isError"], true);
    assert!(!directory.path().join("denied.c").exists());
    let functions = client.tool("ura_get_functions", json!({"handle":handle}));
    assert_eq!(functions["total"], 2);
    for (name, arguments) in [
        (
            "ura_get_function",
            json!({"handle":handle,"address":"140001000"}),
        ),
        (
            "ura_get_disassembly",
            json!({"handle":handle,"address":"140001000","count":10}),
        ),
        (
            "ura_get_cfg",
            json!({"handle":handle,"function":"140001020"}),
        ),
        (
            "ura_get_xrefs",
            json!({"handle":handle,"address":"140001020"}),
        ),
        ("ura_search_strings", json!({"handle":handle})),
        (
            "ura_read_bytes",
            json!({"handle":handle,"address":"140001000","length":4}),
        ),
    ] {
        client.tool(name, arguments);
    }
    for name in [
        "ura_get_function_signature",
        "ura_get_calling_convention",
        "ura_get_stack_variables",
        "ura_get_types",
        "ura_get_high_level_ir",
        "ura_get_type_constraints",
    ] {
        let result = client.tool(
            name,
            json!({"handle":handle,"function":"140001020","limit":40}),
        );
        assert_eq!(result["function"], "0x140001020", "{name}");
        assert_eq!(result["analysisPartial"], false, "{name}");
    }
    let signature = client.tool(
        "ura_get_function_signature",
        json!({"handle":handle,"function":"140001020"}),
    );
    assert_eq!(signature["signature"]["convention"], "win64");
    assert!(signature["signature"]["name"].is_string());
    assert_eq!(
        signature,
        serde_json::to_value(
            shared
                .function_signature(&shared_handle, "140001020")
                .unwrap()
        )
        .unwrap()
    );
    let call_graph = client.tool(
        "ura_get_call_graph",
        json!({"handle":handle,"function":"140001000","depth":1,"maxNodes":100}),
    );
    assert_eq!(call_graph["focus"], "0x140001000");
    assert!(call_graph["nodes"].as_array().unwrap().len() <= 100);
    assert!(call_graph["edges"]
        .as_array()
        .unwrap()
        .iter()
        .any(|edge| edge["from"] == "0x140001000" && edge["to"] == "0x140001020"));
    for name in [
        "ura_get_ir",
        "ura_get_ssa",
        "ura_get_dominators",
        "ura_get_analysis_diagnostics",
    ] {
        let result = client.tool(
            name,
            json!({"handle":handle,"function":"140001020","limit":50}),
        );
        assert_eq!(result["irVersion"], 1);
        let expected = match name {
            "ura_get_ir" => serde_json::to_value(
                shared
                    .ir(&shared_handle, "140001020", false, 0, 50)
                    .unwrap(),
            )
            .unwrap(),
            "ura_get_ssa" => {
                serde_json::to_value(shared.ir(&shared_handle, "140001020", true, 0, 50).unwrap())
                    .unwrap()
            }
            "ura_get_dominators" => serde_json::to_value(
                shared
                    .dominators(&shared_handle, "140001020", 0, 50)
                    .unwrap(),
            )
            .unwrap(),
            _ => serde_json::to_value(
                shared
                    .analysis_diagnostics(&shared_handle, "140001020", 0, 50)
                    .unwrap(),
            )
            .unwrap(),
        };
        assert_eq!(result, expected);
    }
    let denied = client.tool_result(
        "ura_save_project",
        json!({"handle":handle,"project":directory.path().join("denied.ura")}),
    );
    assert_eq!(denied["isError"], true);
    assert_eq!(
        denied["structuredContent"]["error"]["code"],
        "write_disabled"
    );
    let outside = client.tool_result("ura_open_binary", json!({"binary":fixture()}));
    assert_eq!(outside["isError"], true);
    let invalid = client.request(
        "tools/call",
        json!({"name":"ura_read_bytes","arguments":{"handle":handle,"length":"bad"}}),
    );
    assert!(
        invalid["error"].is_object() || invalid["result"]["isError"] == true,
        "{invalid}"
    );
    let malformed = directory.path().join("malformed.exe");
    std::fs::write(&malformed, b"MZ").unwrap();
    assert_eq!(
        client.tool_result("ura_open_binary", json!({"binary":malformed}))["isError"],
        true
    );
    client.tool("ura_close_binary", json!({"handle":handle}));
    assert_eq!(
        client.tool_result("ura_get_binary_info", json!({"handle":handle}))["isError"],
        true
    );
}

#[test]
fn stdio_writes_survive_a_fresh_server() {
    let directory = tempfile::tempdir().unwrap();
    let sample = directory.path().join("sample.exe");
    std::fs::copy(fixture(), &sample).unwrap();
    let project = directory.path().join("analysis.ura");
    let export = directory.path().join("annotations.json");
    {
        let mut client = Client::start(directory.path(), true);
        let opened = client.tool("ura_open_binary", json!({"binary":sample}));
        let handle = opened["handle"].as_str().unwrap();
        client.tool("ura_analyze", json!({"handle":handle}));
        client.tool(
            "ura_save_project",
            json!({"handle":handle,"project":project}),
        );
        client.tool(
            "ura_rename_function",
            json!({"handle":handle,"project":project,"address":"140001000","name":"entry_renamed"}),
        );
        client.tool("ura_add_comment", json!({"handle":handle,"project":project,"address":"140001000","note":"persistent comment"}));
        client.tool(
            "ura_set_function_signature",
            json!({"handle":handle,"project":project,"address":"140001020","convention":"win64","returnType":"u64","parameters":[{"name":"count","register":"rcx","type":"u64"}],"variadic":false}),
        );
        let stack = client.tool(
            "ura_get_stack_variables",
            json!({"handle":handle,"function":"140001020"}),
        );
        let offset = stack["frame"]["slots"][0]["offset"].as_i64().unwrap();
        client.tool(
            "ura_set_variable_type",
            json!({"handle":handle,"project":project,"function":"140001020","offset":offset,"name":"saved_counter","type":"u32"}),
        );
        client.tool(
            "ura_export_analysis",
            json!({"project":project,"export":export}),
        );
        client.tool("ura_set_type_library", json!({"handle":handle,"project":project,"database":{"addressBits":64,"structures":{"Header":{"name":"Header","size":4,"alignment":4,"fields":[{"name":"length","offset":0,"ty":{"kind":"int","bits":32,"signed":false},"size":null,"source":"user"}],"union":false,"source":"user"}},"typedefs":{}}}));
        let definition = client.tool(
            "ura_get_structure",
            json!({"handle":handle,"name":"Header"}),
        );
        assert_eq!(definition["structure"]["fields"][0]["name"], "length");
    }
    let snapshot = ura_project::read_project(&project).unwrap();
    assert_eq!(snapshot.annotations[0].note, "persistent comment");
    assert_eq!(snapshot.function_signatures.len(), 1);
    assert_eq!(
        snapshot.function_signatures[0].signature.parameters[0].name,
        "count"
    );
    assert_eq!(snapshot.stack_variables.len(), 1);
    assert_eq!(
        snapshot.stack_variables[0].name.as_deref(),
        Some("saved_counter")
    );
    assert!(export.exists());
    let before = std::fs::read(&project).unwrap();
    let mut client = Client::start(directory.path(), false);
    let opened = client.tool(
        "ura_open_binary",
        json!({"binary":sample,"project":project}),
    );
    let handle = opened["handle"].as_str().unwrap();
    client.tool("ura_analyze", json!({"handle":handle}));
    let library = client.tool("ura_get_types", json!({"handle":handle}));
    assert_eq!(library["database"]["structures"]["Header"]["size"], 4);
    let functions = client.tool(
        "ura_get_functions",
        json!({"handle":handle,"query":"entry_renamed"}),
    );
    assert_eq!(functions["total"], 1);
    let signature = client.tool(
        "ura_get_function_signature",
        json!({"handle":handle,"function":"140001020"}),
    );
    assert_eq!(signature["signature"]["parameters"][0]["name"], "count");
    let stack = client.tool(
        "ura_get_stack_variables",
        json!({"handle":handle,"function":"140001020"}),
    );
    assert!(stack["frame"]["slots"]
        .as_array()
        .unwrap()
        .iter()
        .any(|slot| slot["userName"] == "saved_counter" && slot["userType"]["kind"] == "int"));
    assert_eq!(std::fs::read(&project).unwrap(), before);
}
