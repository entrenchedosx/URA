use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use ura_core::AnalysisOptions;
use ura_service::{PathPolicy, Service};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn fixture(name: &str) -> PathBuf {
    repo_root().join("tests").join("fixtures").join(name)
}

#[test]
fn executable_patch_workflow_preserves_original_and_exports_effective_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let sample = directory.path().join("sample.exe");
    std::fs::copy(fixture("ura64.exe"), &sample).unwrap();
    let original = std::fs::read(&sample).unwrap();
    let project = directory.path().join("project.ura");
    let output = directory.path().join("patched.exe");
    let invoke = |args: &[&str], writes: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ura-cli"));
        command.arg("--allow").arg(directory.path());
        if writes {
            command.arg("--enable-writes");
        }
        command.args(args).output().unwrap()
    };
    let init = invoke(
        &[
            "patch",
            text(&sample),
            "init",
            "--destination",
            text(&project),
        ],
        true,
    );
    assert!(init.status.success(), "{}", stderr(&init));
    let instruction = [
        "patch",
        text(&sample),
        "--project",
        text(&project),
        "--json",
        "instruction",
        "--space",
        "va",
        "--address",
        "140001020",
        "--budget",
        "1",
        "--assembly",
        "ret",
        "--apply",
    ];
    let denied = invoke(&instruction, false);
    assert!(!denied.status.success());
    assert_eq!(json(&denied)["error"]["code"], "write_disabled");
    let applied = invoke(&instruction, true);
    assert!(applied.status.success(), "{}", stderr(&applied));
    assert_eq!(json(&applied)["changedBytes"], 1);
    let read = invoke(
        &[
            "patch",
            text(&sample),
            "--project",
            text(&project),
            "read",
            "--space",
            "offset",
            "--address",
            "220",
            "--length",
            "1",
        ],
        false,
    );
    assert!(read.status.success(), "{}", stderr(&read));
    assert_eq!(json(&read)["current"], serde_json::json!([195]));
    let export = invoke(
        &[
            "patch",
            text(&sample),
            "--project",
            text(&project),
            "export",
            "--destination",
            text(&output),
        ],
        true,
    );
    assert!(export.status.success(), "{}", stderr(&export));
    assert_eq!(std::fs::read(&sample).unwrap(), original);
    let bytes = std::fs::read(output).unwrap();
    assert_eq!(bytes.len(), original.len());
    assert_eq!(bytes[0x220], 0xc3);
    assert_eq!(&bytes[0x221..], &original[0x221..]);
    let undo = invoke(
        &[
            "patch",
            text(&sample),
            "--project",
            text(&project),
            "history",
            "--action",
            "undo",
        ],
        true,
    );
    assert!(undo.status.success(), "{}", stderr(&undo));
    assert_eq!(json(&undo)["changedBytes"], 0);
}

#[test]
fn decompile_json_matches_service_and_plain_output_is_c_like() {
    let sample = fixture("ura64.exe");
    let output = run([
        "decompile",
        sample.to_str().unwrap(),
        "--function",
        "140001020",
        "--ast",
        "--json",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    let value = json(&output);
    assert_eq!(value["syntax"], "c-like");
    assert_eq!(value["ast"]["address"], "0x140001020");
    let mut service = Service::new(PathPolicy::allow_all(), false);
    let handle = service.open_binary(&sample, None).unwrap().handle;
    service.analyze(&handle, &Default::default()).unwrap();
    let expected = serde_json::to_value(
        service
            .decompile(&handle, "140001020", 0, 200, true)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(value, expected);
    let plain = run([
        "decompile",
        sample.to_str().unwrap(),
        "--function",
        "140001020",
    ]);
    assert!(plain.status.success());
    assert!(stdout(&plain).contains("Reconstructed C-like"));
}

#[test]
fn cli_type_library_writes_are_explicit_and_persist_for_structure_queries() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("types.ura");
    let definitions = directory.path().join("types.json");
    let sample = fixture("ura64.exe");
    let mut service = Service::new(PathPolicy::allow_all(), true);
    let handle = service.open_binary(&sample, None).unwrap().handle;
    service.save_project(&handle, &project, None).unwrap();
    let database = serde_json::json!({"addressBits":64,"structures":{"Header":{"name":"Header","size":4,"alignment":4,"fields":[{"name":"length","offset":0,"ty":{"kind":"int","bits":32,"signed":false},"source":"user","size":null}],"union":false,"source":"user"}},"typedefs":{}});
    std::fs::write(&definitions, database.to_string()).unwrap();
    let invoke = |write: bool, args: &[&str]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ura-cli"));
        command
            .arg("--allow")
            .arg(repo_root())
            .arg("--allow")
            .arg(directory.path());
        if write {
            command.arg("--enable-writes");
        }
        command
            .arg("type-library")
            .arg(&sample)
            .arg("--project")
            .arg(&project)
            .arg("--json")
            .args(args)
            .output()
            .unwrap()
    };
    let input = definitions.to_str().unwrap();
    let denied = invoke(false, &["--import", input]);
    assert!(!denied.status.success());
    assert_eq!(json(&denied)["error"]["code"], "write_disabled");
    let saved = invoke(true, &["--import", input]);
    assert!(saved.status.success(), "{}", stderr(&saved));
    let query = invoke(false, &["--name", "Header"]);
    assert!(query.status.success(), "{}", stderr(&query));
    assert_eq!(json(&query)["structure"]["fields"][0]["name"], "length");
    let outside = invoke(true, &["--import", "C:\\Windows\\win.ini"]);
    assert!(!outside.status.success());
    assert_eq!(json(&outside)["error"]["code"], "path_denied");
}

fn run<S: AsRef<OsStr>>(args: impl IntoIterator<Item = S>) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ura-cli"))
        .arg("--allow")
        .arg(repo_root())
        .args(args)
        .output()
        .expect("ura-cli should run")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

fn json(output: &Output) -> Value {
    serde_json::from_str(&stdout(output)).unwrap_or_else(|error| {
        panic!(
            "stdout was not valid JSON: {error}\nstdout: {}\nstderr: {}",
            stdout(output),
            stderr(output)
        )
    })
}

fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn raw_ssa_dominators_and_diagnostics_match_shared_service() {
    let binary = fixture("ura64.exe");
    let mut service = Service::new(PathPolicy::allow_all(), false);
    let h = service.open_binary(&binary, None).unwrap().handle;
    service.analyze(&h, &Default::default()).unwrap();
    for ssa in [false, true] {
        let mut args = vec![
            "ir",
            text(&binary),
            "--function",
            "140001020",
            "--offset",
            "3",
            "--limit",
            "7",
            "--json",
        ];
        if ssa {
            args.push("--ssa");
        }
        let output = run(args);
        assert!(output.status.success(), "{}", stderr(&output));
        let expected = service.ir(&h, "140001020", ssa, 3, 7).unwrap();
        assert_eq!(json(&output), serde_json::to_value(expected).unwrap());
    }
    for command in ["dominators", "diagnostics"] {
        let output = run([
            command,
            text(&binary),
            "--function",
            "140001020",
            "--limit",
            "7",
            "--json",
        ]);
        assert!(output.status.success(), "{}", stderr(&output));
        let expected = if command == "dominators" {
            serde_json::to_value(service.dominators(&h, "140001020", 0, 7).unwrap()).unwrap()
        } else {
            serde_json::to_value(service.analysis_diagnostics(&h, "140001020", 0, 7).unwrap())
                .unwrap()
        };
        assert_eq!(json(&output), expected);
    }
    let output = run([
        "ir",
        text(&binary),
        "--function",
        "140001020",
        "--limit",
        "501",
        "--json",
    ]);
    assert!(!output.status.success());
    assert_eq!(json(&output)["error"]["code"], "limit_exceeded");
}

#[test]
fn info_reports_identity_in_text_and_json() {
    let binary = fixture("ura64.exe");
    let text_output = run(["info", text(&binary)]);
    assert!(text_output.status.success(), "{}", stderr(&text_output));
    let rendered = stdout(&text_output);
    assert!(rendered.contains("Entry point: 0x140001000"));
    assert!(rendered.contains(".rdata"));
    assert!(rendered.contains("b3af30012bbcd6fc3186ef5b65d3c8460bc09cade3870a614fbf2bd3d41eb92d"));

    let json_output = run(["info", text(&binary), "--json"]);
    assert!(json_output.status.success(), "{}", stderr(&json_output));
    let value = json(&json_output);
    assert_eq!(value["schemaVersion"], 1);
    assert_eq!(value["handle"], "bin1");
    assert_eq!(value["info"]["format"], "PE");
    assert_eq!(value["info"]["architecture"], "x86-64");
    assert_eq!(value["info"]["entryPoint"], "0x140001000");
    assert_eq!(value["info"]["imageBase"], "0x140000000");
    assert_eq!(value["sections"].as_array().unwrap().len(), 2);
    assert!(value["attachedProject"].is_null());
}

#[test]
fn analyze_functions_and_cfg_expose_analysis_results() {
    let binary = fixture("ura64.exe");
    let output = run([
        "analyze",
        text(&binary),
        "--json",
        "--max-instructions",
        "1000",
        "--no-follow-calls",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    let value = json(&output);
    assert_eq!(value["options"]["maxInstructions"], 1000);
    assert_eq!(value["options"]["followCalls"], false);

    let output = run([
        "analyze",
        text(&binary),
        "--json",
        "--max-instructions",
        "64",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    let value = json(&output);
    assert_eq!(value["report"]["functionCount"], 2);
    assert_eq!(value["report"]["instructionCount"], 15);

    let output = run([
        "functions",
        text(&binary),
        "--json",
        "--sort",
        "instructions",
        "--limit",
        "1",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    let value = json(&output);
    assert_eq!(value["total"], 2);
    assert_eq!(value["returned"], 1);
    assert_eq!(value["limit"], 1);
    assert_eq!(value["functions"][0]["instructionCount"], 8);

    let output = run([
        "cfg",
        text(&binary),
        "--function",
        "0x140001020",
        "--max-cfg-blocks",
        "2",
        "--json",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    let value = json(&output);
    assert_eq!(value["function"]["name"], "sub_140001020");
    assert_eq!(value["truncated"], true);
    assert_eq!(value["blocks"].as_array().unwrap().len(), 2);
    assert_eq!(value["blocks"][1]["successors"][0]["kind"], "taken");
    assert_eq!(value["blocks"][1]["successors"][0]["target"], "0x140001026");
}

#[test]
fn disassembly_hex_strings_and_xrefs_are_queryable() {
    let binary = fixture("ura64.exe");
    let output = run([
        "disasm",
        text(&binary),
        "--address",
        "0x140001000",
        "--count",
        "2",
        "--json",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    let value = json(&output);
    let instructions = value["instructions"].as_array().unwrap();
    assert_eq!(instructions.len(), 2);
    assert_eq!(instructions[0]["address"], "0x140001000");
    assert_eq!(instructions[0]["text"], "push rbp");
    assert_eq!(instructions[0]["bytes"], "55");

    let output = run([
        "hex",
        text(&binary),
        "--offset",
        "0x400",
        "--length",
        "16",
        "--json",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    let value = json(&output);
    assert_eq!(value["address"], "0x140002000");
    assert_eq!(value["section"], ".rdata");
    assert_eq!(value["returnedLength"], 16);
    assert_eq!(
        value["hex"],
        "55 52 41 20 66 69 78 74 75 72 65 20 73 74 72 69"
    );
    assert_eq!(value["ascii"], "URA fixture stri");

    let output = run(["strings", text(&binary), "--json", "--limit", "20"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let value = json(&output);
    let strings = value["strings"].as_array().unwrap();
    assert!(strings
        .iter()
        .any(|entry| entry["value"] == "URA fixture string"));
    assert!(strings.iter().any(|entry| entry["value"] == "Wide URA"));
    assert_eq!(value["total"], 4);

    let output = run(["xrefs", text(&binary), "--address", "0x140001020", "--json"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let value = json(&output);
    assert_eq!(value["total"], 1);
    let xrefs = value["xrefs"].as_array().unwrap();
    assert_eq!(xrefs[0]["from"], "0x140001004");
    assert_eq!(xrefs[0]["kind"], "call");
    assert_eq!(xrefs[0]["fromName"], "sub_140001000");
    assert_eq!(xrefs[0]["toName"], "sub_140001020");
}

#[test]
fn errors_are_structured_json_with_exit_code_one() {
    let binary = fixture("ura64.exe");

    let output = run([
        "hex",
        text(&binary),
        "--offset",
        "0x200",
        "--length",
        "0",
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).is_empty());
    let value = json(&output);
    assert_eq!(value["schemaVersion"], 1);
    assert_eq!(value["error"]["code"], "limit_exceeded");

    let outside = tempfile::tempdir().unwrap();
    let outside_file = outside.path().join("sample.bin");
    std::fs::write(&outside_file, b"MZ").unwrap();
    let output = run(["info", text(&outside_file), "--json"]);
    assert_eq!(output.status.code(), Some(1));
    let value = json(&output);
    assert_eq!(value["error"]["code"], "path_denied");
    assert!(!value["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with(r"\\?\"));

    let missing = outside.path().join("missing.ura");
    let output = run([
        "--allow",
        text(outside.path()),
        "info",
        text(&binary),
        "--project",
        text(&missing),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(1));
    let value = json(&output);
    assert_eq!(value["error"]["code"], "project_not_found");

    let text_output = run(["info", text(&missing)]);
    assert_eq!(text_output.status.code(), Some(1));
    assert!(stderr(&text_output).starts_with("error: "));
    assert!(stdout(&text_output).is_empty());
}

#[test]
fn project_function_names_reach_the_cli() {
    let directory = tempfile::tempdir().unwrap();
    let project_path = directory.path().join("fixture.ura");

    let mut service = Service::new(
        PathPolicy::new([repo_root(), directory.path().to_path_buf()]).unwrap(),
        true,
    );
    let opened = service.open_binary(&fixture("ura64.exe"), None).unwrap();
    service
        .analyze(&opened.handle, &AnalysisOptions::default())
        .unwrap();
    service
        .save_project(&opened.handle, &project_path, Some("CLI"))
        .unwrap();
    service
        .rename_function(&opened.handle, &project_path, "0x140001020", "loop_fn")
        .unwrap();

    let output = run([
        "--allow",
        text(directory.path()),
        "functions",
        text(&fixture("ura64.exe")),
        "--project",
        text(&project_path),
        "--json",
        "--query",
        "loop_fn",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    let value = json(&output);
    assert_eq!(value["total"], 1);
    assert_eq!(value["functions"][0]["name"], "loop_fn");
    assert_eq!(value["functions"][0]["address"], "0x140001020");

    let output = run([
        "--allow",
        text(directory.path()),
        "info",
        text(&fixture("ura64.exe")),
        "--project",
        text(&project_path),
        "--json",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    let attached = json(&output)["attachedProject"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(attached.ends_with("fixture.ura"), "{attached}");
}

#[test]
fn decompiler_commands_match_the_shared_service_and_render_text() {
    let binary = fixture("ura64.exe");
    let mut service = Service::new(PathPolicy::allow_all(), false);
    let handle = service.open_binary(&binary, None).unwrap().handle;
    service.analyze(&handle, &Default::default()).unwrap();

    let output = run([
        "signature",
        text(&binary),
        "--function",
        "140001020",
        "--json",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        json(&output),
        serde_json::to_value(service.function_signature(&handle, "140001020").unwrap()).unwrap()
    );
    let rendered = stdout(&run([
        "signature",
        text(&binary),
        "--function",
        "140001020",
    ]));
    // The fixture returns a value derived from an opaque call; its type must
    // remain unknown rather than becoming an inferred integer through copies.
    assert_eq!(
        service
            .function_signature(&handle, "140001020")
            .unwrap()
            .signature
            .return_value
            .ty
            .display(),
        "unknown64"
    );
    assert!(rendered.contains("unknown64"));
    assert!(rendered.contains("Convention: win64"));

    let output = run(["stack", text(&binary), "--function", "140001020", "--json"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        json(&output),
        serde_json::to_value(service.stack_frame(&handle, "140001020").unwrap()).unwrap()
    );

    let output = run(["types", text(&binary), "--function", "140001020", "--json"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        json(&output),
        serde_json::to_value(service.inferred_types(&handle, "140001020").unwrap()).unwrap()
    );

    let output = run([
        "highlevel",
        text(&binary),
        "--function",
        "140001020",
        "--offset",
        "0",
        "--limit",
        "9",
        "--json",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        json(&output),
        serde_json::to_value(service.high_level(&handle, "140001020", 0, 9).unwrap()).unwrap()
    );
    let rendered = stdout(&run([
        "highlevel",
        text(&binary),
        "--function",
        "140001020",
        "--limit",
        "9",
    ]));
    assert!(rendered.contains("experimental-foundations"));
    assert!(rendered.contains("recovered high-level IR"));

    let typed = run([
        "highlevel",
        text(&binary),
        "--function",
        "140001020",
        "--limit",
        "9",
        "--ast",
        "--json",
    ]);
    assert!(typed.status.success(), "{}", stderr(&typed));
    assert_eq!(
        json(&typed),
        serde_json::to_value(
            service
                .high_level_with_ast(&handle, "140001020", 0, 9, true)
                .unwrap()
        )
        .unwrap()
    );
    let semantic = run([
        "highlevel",
        text(&binary),
        "--function",
        "140001020",
        "--semantic",
        "--json",
    ]);
    assert!(semantic.status.success(), "{}", stderr(&semantic));
    let result = json(&semantic);
    assert_eq!(result["semantic"]["complete"], true);
    assert!(result["semantic"]["nodes"].as_array().unwrap().len() > 10);

    let output = run([
        "callgraph",
        text(&binary),
        "--function",
        "140001000",
        "--depth",
        "1",
        "--max-nodes",
        "50",
        "--json",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        json(&output),
        serde_json::to_value(
            service
                .call_graph(&handle, Some("140001000"), 1, 50)
                .unwrap()
        )
        .unwrap()
    );
    let rendered = stdout(&run([
        "callgraph",
        text(&binary),
        "--function",
        "140001000",
        "--depth",
        "1",
        "--max-nodes",
        "50",
    ]));
    assert!(rendered.contains("Call graph:"));
    assert!(rendered.contains("0x140001020"));
}
