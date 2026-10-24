#![cfg(windows)]
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use ura_extensions::{runtime::Runtime, ExecutionConfig, ExtensionHost};
use ura_service::{PathPolicy, Service};
#[test]
fn batch_handles_failures_resume_and_never_clobbers_exports() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("output");
    std::fs::create_dir(&output).unwrap();
    let invalid = dir.path().join("invalid.bin");
    std::fs::write(&invalid, b"not an executable").unwrap();
    let script = root.join("sdk/examples/inventory.py");
    let mut config = ExecutionConfig {
        enabled: true,
        runtime: Some(Runtime::new(&root.join("target/python-runtime-3.14.9")).unwrap()),
        registry: dir.path().join("plugins"),
        ..Default::default()
    };
    config.capabilities.insert("files.export".into());
    config.trust_script(&script).unwrap();
    let h = ExtensionHost::new(
        Arc::new(Mutex::new(Service::new(PathPolicy::allow_all(), true))),
        config,
    )
    .unwrap();
    let request = json!({"operation":"batch","action":"start","paths":[root.join("tests/fixtures/ura64.exe"),invalid],"script":script,"destination":output});
    fn wait(h: &ExtensionHost, id: &Value) -> Value {
        let start = Instant::now();
        loop {
            let r = h
                .rpc(json!({"operation":"batch","action":"status","id":id}))
                .unwrap();
            if r["state"] != "running" {
                return r;
            }
            assert!(start.elapsed() < Duration::from_secs(15));
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let batch = h.rpc(request.clone()).unwrap();
    let report = wait(&h, &batch["id"]);
    assert_eq!(report["rows"][0]["state"], "complete", "{report}");
    assert_eq!(report["rows"][1]["state"], "failed");
    let path = PathBuf::from(report["rows"][0]["output"].as_str().unwrap());
    let original = std::fs::read(&path).unwrap();
    h.rpc(json!({"operation":"batch","action":"close","id":batch["id"]}))
        .unwrap();
    let mut resume = request.clone();
    resume["resume"] = json!(true);
    let b = h.rpc(resume).unwrap();
    assert_eq!(wait(&h, &b["id"])["rows"][0]["state"], "skipped");
    assert_eq!(std::fs::read(&path).unwrap(), original);
    h.rpc(json!({"operation":"batch","action":"close","id":b["id"]}))
        .unwrap();
    let b = h.rpc(request).unwrap();
    assert_eq!(wait(&h, &b["id"])["rows"][0]["state"], "failed");
    assert_eq!(std::fs::read(&path).unwrap(), original);
}

#[test]
fn cancelled_active_script_resumes_without_overwriting_attempt() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let d = tempfile::tempdir().unwrap();
    let output = d.path().join("results");
    std::fs::create_dir(&output).unwrap();
    let marker = d.path().join("ready");
    let script = d.path().join("resume.py");
    let code=format!("from pathlib import Path\nimport time\np=Path({:?})\nif not p.exists():\n    p.write_text('owned fixture')\n    time.sleep(5)\nprint('finished')\n",marker.to_string_lossy());
    std::fs::write(&script, code).unwrap();
    let mut c = ExecutionConfig {
        enabled: true,
        runtime: Some(Runtime::new(&root.join("target/python-runtime-3.14.9")).unwrap()),
        registry: d.path().join("plugins"),
        ..Default::default()
    };
    c.capabilities.insert("files.export".into());
    c.trust_script(&script).unwrap();
    let h = ExtensionHost::new(
        Arc::new(Mutex::new(Service::new(PathPolicy::allow_all(), true))),
        c,
    )
    .unwrap();
    let request = json!({"operation":"batch","action":"start","paths":[root.join("tests/fixtures/ura64.exe")],"script":script,"destination":output});
    let b = h.rpc(request.clone()).unwrap();
    let start = Instant::now();
    while !marker.exists() {
        assert!(start.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(10));
    }
    h.rpc(json!({"operation":"batch","action":"cancel","id":b["id"]}))
        .unwrap();
    fn wait(h: &ExtensionHost, id: &Value) -> Value {
        let start = Instant::now();
        loop {
            let r = h
                .rpc(json!({"operation":"batch","action":"status","id":id}))
                .unwrap();
            if r["state"] != "running" {
                return r;
            }
            assert!(start.elapsed() < Duration::from_secs(15));
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let first = wait(&h, &b["id"]);
    assert_eq!(first["state"], "cancelled");
    let old = PathBuf::from(first["rows"][0]["output"].as_str().unwrap());
    let bytes = std::fs::read(&old).unwrap();
    h.rpc(json!({"operation":"batch","action":"close","id":b["id"]}))
        .unwrap();
    let mut request = request;
    request["resume"] = json!(true);
    let b = h.rpc(request).unwrap();
    let second = wait(&h, &b["id"]);
    assert_eq!(second["rows"][0]["state"], "complete", "{second}");
    assert_ne!(second["rows"][0]["output"], first["rows"][0]["output"]);
    assert_eq!(std::fs::read(old).unwrap(), bytes);
}
