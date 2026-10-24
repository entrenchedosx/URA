#![cfg(windows)]
use std::{path::PathBuf, process::Command};
#[test]
fn python_cli_file_permissions_and_exit_statuses() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("script.py");
    let invoke = |enabled: bool, timeout: &str| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ura-cli"));
        cmd.arg("--allow")
            .arg(&root)
            .arg("--allow")
            .arg(dir.path())
            .arg("--python-runtime")
            .arg(root.join("target/python-runtime-3.14.9"))
            .arg("--extensions-dir")
            .arg(dir.path().join("plugins"))
            .arg("--trust-script")
            .arg(&script);
        if enabled {
            cmd.arg("--enable-scripting");
        }
        cmd.arg("script")
            .arg(root.join("tests/fixtures/ura64.exe"))
            .arg("--script")
            .arg(&script)
            .arg("--timeout-ms")
            .arg(timeout)
            .output()
            .unwrap()
    };
    std::fs::write(&script,"import ura\nif __name__ == '__main__': print(next(ura.current_project().functions()).name)\n").unwrap();
    let denied = invoke(false, "30000");
    assert_eq!(denied.status.code(), Some(9));
    let result = invoke(true, "30000");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let r: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(r["state"], "complete");
    assert!(!r["stdout"].as_str().unwrap().is_empty());
    std::fs::write(&script, "raise ValueError('fixture')").unwrap();
    let result = invoke(true, "30000");
    assert_eq!(result.status.code(), Some(3));
    let r: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(r["state"], "pythonError");
    std::fs::write(&script, "while True: pass").unwrap();
    assert_eq!(invoke(true, "100").status.code(), Some(4));
}

#[test]
fn interactive_malformed_json_is_rejected_without_losing_transport() {
    use std::io::{BufRead, BufReader, Write};
    use std::process::Stdio;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ura-cli"))
        .arg("--allow")
        .arg(&root)
        .arg("--extensions-dir")
        .arg(dir.path().join("plugins"))
        .arg("extensions")
        .arg("--binary")
        .arg(root.join("tests/fixtures/ura64.exe"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    for request in [
        "[]",
        "123",
        "\"text\"",
        r#"{"operation":"plugins","action":"list"}"#,
    ] {
        writeln!(input, "{request}").unwrap();
        input.flush().unwrap();
        line.clear();
        output.read_line(&mut line).unwrap();
        let result: serde_json::Value = serde_json::from_str(&line).unwrap();
        if request.starts_with('{') {
            assert!(result["result"]["plugins"].is_array());
        } else {
            assert_eq!(result["error"]["code"], "extension_error");
        }
    }
    drop(input);
    assert!(child.wait().unwrap().success());
}
