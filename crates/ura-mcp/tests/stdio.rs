//! Exercise the shipped executable and actual newline-delimited MCP transport.
use serde_json::{json, Value};
use std::{
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc,
    time::Duration,
};

struct Client {
    child: Child,
    input: ChildStdin,
    replies: mpsc::Receiver<Value>,
    id: u64,
}
impl Client {
    fn start(root: &Path, writes: bool) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ura-mcp"));
        command.args(["--allow", root.to_str().unwrap(), "--log", "off"]);
        if writes {
            command.arg("--enable-writes");
        }
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

#[test]
fn stdio_queries_errors_and_read_only_permissions() {
    let directory = tempfile::tempdir().unwrap();
    let sample = directory.path().join("sample.exe");
    std::fs::copy(fixture(), &sample).unwrap();
    let mut client = Client::start(directory.path(), false);
    let tools = client.request("tools/list", json!({}));
    let listed = tools["result"]["tools"].as_array().unwrap();
    assert_eq!(listed.len(), 29);
    for tool in listed {
        let expected = !matches!(
            tool["name"].as_str().unwrap(),
            "ura_rename_function"
                | "ura_add_comment"
                | "ura_save_project"
                | "ura_export_analysis"
                | "ura_close_binary"
                | "ura_set_function_signature"
                | "ura_set_variable_type"
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
        "ura_get_structure",
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
