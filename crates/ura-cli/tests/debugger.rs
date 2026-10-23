#![cfg(all(windows, target_arch = "x86_64"))]
use serde_json::{json, Value};
use std::{
    io::{BufRead, BufReader, Write},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
#[path = "../../../tests/support/debug_fixture.rs"]
mod debug_fixture;
#[test]
fn interactive_debugger_real_launch_step_memory_and_permissions() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let target = debug_fixture::fixture();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ura-cli"))
        .arg("--allow")
        .arg(&root)
        .arg("--enable-debug-launch")
        .arg("--debug-target")
        .arg(&target)
        .arg("debug")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut rpc = |value: Value| {
        writeln!(input, "{value}").unwrap();
        input.flush().unwrap();
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        serde_json::from_str::<Value>(&line).unwrap()
    };
    let launched = rpc(json!({"operation":"launch","executable":target}));
    let session = launched["result"]["session"].clone();
    assert!(session.is_string(), "{launched}");
    let mut wait = |state: &str| {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let response = rpc(json!({"operation":"status","session":session}));
            if response["result"]["state"] == state {
                break response;
            }
            assert!(Instant::now() < deadline, "{response}");
            std::thread::sleep(Duration::from_millis(15));
        }
    };
    let paused = wait("paused");
    let ip = paused["result"]["registers"]["values"]["rip"].clone();
    let memory = rpc(json!({"operation":"readMemory","session":session,"address":ip,"length":16}));
    assert_eq!(memory["result"]["read"], 16);
    assert!(rpc(json!({"operation":"capabilities"}))["result"]["hardwareSlotsPerThread"] == 4);
    assert!(rpc(json!({"operation":"snapshot","session":session,"action":"capture","address":ip,"length":16}))["error"].is_object());
    assert!(
        rpc(
            json!({"operation":"trace","session":session,"action":"start","config":{"mode":"events","maxEvents":4}})
        )["result"]["active"]
            == true
    );
    rpc(json!({"operation":"trace","session":session,"action":"stop"}));
    assert!(
        rpc(json!({"operation":"trace","session":session,"action":"read","limit":4}))["result"]
            ["events"]
            .is_array()
    );
    let denied = rpc(json!({"operation":"attach","pid":4,"executable":target}));
    assert!(denied["error"].is_object());
    let terminated = rpc(json!({"operation":"terminate","session":session}));
    assert_eq!(terminated["result"]["state"], "terminating");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let response = rpc(json!({"operation":"status","session":session}));
        if response["result"]["state"] == "exited" {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(input);
    assert!(child.wait().unwrap().success());
}
