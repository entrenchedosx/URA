#![cfg(windows)]
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use ura_extensions::{
    plugins::{Registry, CAPABILITIES},
    runtime::Runtime,
    ExecutionConfig, ExtensionHost,
};
use ura_service::{PathPolicy, Service};
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn package(path: &Path, source: &Path) {
    let file = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    for entry in std::fs::read_dir(source).unwrap() {
        let e = entry.unwrap();
        if !e.file_type().unwrap().is_file() {
            continue;
        }
        zip.start_file(
            e.file_name().to_str().unwrap(),
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        zip.write_all(&std::fs::read(e.path()).unwrap()).unwrap();
    }
    zip.finish().unwrap();
}
fn make() -> (
    ExtensionHost,
    Arc<Mutex<Service>>,
    String,
    tempfile::TempDir,
) {
    let folder = tempfile::tempdir().unwrap();
    let mut s = Service::new(PathPolicy::allow_all(), true);
    let h = s
        .open_binary(&root().join("tests/fixtures/ura64.exe"), None)
        .unwrap()
        .handle;
    s.analyze(&h, &Default::default()).unwrap();
    let s = Arc::new(Mutex::new(s));
    let c = ExecutionConfig {
        enabled: true,
        snippets: true,
        plugin_management: true,
        runtime: Some(Runtime::new(&root().join("target/python-runtime-3.14.9")).unwrap()),
        registry: folder.path().join("plugins"),
        capabilities: CAPABILITIES.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    };
    (ExtensionHost::new(s.clone(), c).unwrap(), s, h, folder)
}
fn wait(h: &ExtensionHost, job: &Value) -> Value {
    let start = Instant::now();
    loop {
        let r = h.job(job["job"].as_str().unwrap()).unwrap();
        if r["state"] != "running" {
            return r;
        }
        assert!(start.elapsed() < Duration::from_secs(15));
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn install(h: &ExtensionHost, dir: &Path, name: &str) -> String {
    let path = dir.join(format!("{name}.zip"));
    package(&path, &root().join("sdk/examples/plugins").join(name));
    let p = h
        .rpc(json!({"operation":"plugins","action":"install","path":path}))
        .unwrap();
    assert_eq!(p["enabled"], false);
    let id = p["manifest"]["id"].as_str().unwrap().to_string();
    h.rpc(json!({"operation":"plugins","action":"enable","id":id,"capabilities":p["manifest"]["requiredCapabilities"]})).unwrap();
    id
}
#[test]
fn genuine_analyzer_command_and_changed_code_revokes_grants() {
    let (h, _s, handle, dir) = make();
    let id = install(&h, dir.path(), "candidate_analyzer");
    let r = h
        .rpc(
            json!({"operation":"plugins","action":"run","id":id,"kind":"analyzer","handle":handle}),
        )
        .unwrap();
    let r = wait(&h, &r);
    assert_eq!(r["state"], "complete", "{r}");
    assert!(!r["findings"].as_array().unwrap().is_empty());
    assert_eq!(r["findings"][0]["confidence"], "observed");
    assert_eq!(r["findings"][0]["sourcePlugin"], id);
    let r=h.rpc(json!({"operation":"plugins","action":"run","id":id,"command":"inventory","handle":handle})).unwrap();
    assert!(wait(&h, &r)["value"]["names"].as_array().unwrap().len() > 1);
    std::fs::write(
        dir.path().join("plugins").join(&id).join("new.py"),
        "# changed",
    )
    .unwrap();
    assert_eq!(
        h.rpc(json!({"operation":"plugins","action":"inspect","id":id}))
            .unwrap()["enabled"],
        false
    );
    assert!(h
        .rpc(
            json!({"operation":"plugins","action":"run","id":id,"kind":"analyzer","handle":handle})
        )
        .is_err());
}
#[test]
fn loader_uses_custom_container_and_shared_analysis() {
    let (h, _s, _handle, dir) = make();
    let id = install(&h, dir.path(), "container_loader");
    let path = dir.path().join("sample.ura0");
    let mut bytes = b"URA0".to_vec();
    bytes.extend(0x1000u64.to_le_bytes());
    bytes.extend(0u32.to_le_bytes());
    bytes.extend([0xb8, 42, 0, 0, 0, 0xc3]);
    std::fs::write(&path, bytes).unwrap();
    let job = h
        .rpc(json!({"operation":"plugins","action":"run","id":id,"kind":"loader","path":path}))
        .unwrap();
    let r = wait(&h, &job);
    assert_eq!(r["state"], "complete", "{r}");
    let accepted = h
        .rpc(json!({"operation":"plugins","action":"accept","job":job["job"]}))
        .unwrap();
    assert_eq!(accepted["kind"], "loader");
    assert!(accepted["analysis"].to_string().contains("1000"));
    let bytes=h.rpc(json!({"operation":"image","action":"memory","handle":accepted["image"],"address":"0x1000","length":6})).unwrap();
    assert!(bytes.to_string().contains("184"));
}
#[test]
fn toy_processor_has_core_cfg_and_real_navigation_without_fake_ir() {
    let (h, _s, _handle, dir) = make();
    let id = install(&h, dir.path(), "toy_processor");
    let path = dir.path().join("sample.toy");
    std::fs::write(&path, [16, 1, 48, 7, 32, 2, 255, 0, 255]).unwrap();
    let job=h.rpc(json!({"operation":"plugins","action":"run","id":id,"kind":"processor","path":path,"base":"0x0"})).unwrap();
    let r = wait(&h, &job);
    assert_eq!(r["state"], "complete", "{r}");
    let accepted = h
        .rpc(json!({"operation":"plugins","action":"accept","job":job["job"]}))
        .unwrap();
    assert_eq!(accepted["capabilities"]["ir"], false);
    let page=h.rpc(json!({"operation":"processor","action":"page","handle":accepted["handle"],"address":"0x7"})).unwrap();
    assert_eq!(page["instructions"][0]["mnemonic"], "nop");
    assert!(page["blocks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|b| b["successors"].as_array().unwrap().len() == 2));
    assert!(h
        .rpc(json!({"operation":"processor","action":"ir","handle":accepted["handle"]}))
        .is_err());
}
#[test]
fn unsafe_zip_and_registry_capacity_fail_without_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let r = Registry::new(&dir.path().join("registry")).unwrap();
    for member in [
        "../outside.py",
        "C:/outside.py",
        "dir\\outside.py",
        "NUL.py",
        "enabled.json/x",
    ] {
        let path = dir.path().join("unsafe.zip");
        let mut zip = zip::ZipWriter::new(std::fs::File::create(&path).unwrap());
        zip.start_file(member, zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"bad").unwrap();
        zip.finish().unwrap();
        assert!(r.install(&path).is_err());
    }
    assert!(!dir.path().join("outside.py").exists());
    assert_eq!(r.list().unwrap()["plugins"], json!([]));
    let path = dir.path().join("valid.zip");
    package(&path, &root().join("sdk/examples/plugins/event_observer"));
    let p = r.install(&path).unwrap();
    let caps: BTreeSet<_> = p.manifest.required_capabilities.clone();
    r.enable(&p.manifest.id, caps.clone(), json!({})).unwrap();
    let before = std::fs::read(r.root.join("enabled.json")).unwrap();
    assert!(r
        .enable(&p.manifest.id, caps, json!({"huge":"x".repeat(17000)}))
        .is_err());
    assert_eq!(std::fs::read(r.root.join("enabled.json")).unwrap(), before);
    r.disable(&p.manifest.id).unwrap();
    assert!(!r.inspect(&p.manifest.id).unwrap().enabled);
    r.uninstall(&p.manifest.id).unwrap();
}

#[test]
fn ordered_event_hooks_include_fast_completion_and_close_then_unsubscribe() {
    let (h, s, handle, dir) = make();
    let id = install(&h, dir.path(), "event_observer");
    {
        let mut s = s.lock().unwrap();
        s.analyze(&handle, &Default::default()).unwrap();
        s.close_binary(&handle).unwrap();
    }
    let start = Instant::now();
    let mut kinds = Vec::new();
    loop {
        let jobs = h
            .rpc(json!({"operation":"scripts","action":"list"}))
            .unwrap();
        kinds.clear();
        for job in jobs["jobs"].as_array().unwrap() {
            let r = h.job(job.as_str().unwrap()).unwrap();
            if r["sourcePlugin"] == id && r["state"] == "complete" {
                kinds.push((
                    r["value"]["sequence"].as_u64().unwrap(),
                    r["value"]["kind"].as_str().unwrap().to_string(),
                ));
            }
        }
        if kinds.len() >= 3 {
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(10), "{kinds:?}");
        std::thread::sleep(Duration::from_millis(10));
    }
    kinds.sort();
    assert_eq!(
        kinds.iter().map(|(_, k)| k.as_str()).collect::<Vec<_>>(),
        vec!["analysis.started", "analysis.completed", "project.closed"]
    );
    h.rpc(json!({"operation":"plugins","action":"disable","id":id}))
        .unwrap();
    let before = h
        .rpc(json!({"operation":"scripts","action":"list"}))
        .unwrap()["jobs"]
        .as_array()
        .unwrap()
        .len();
    s.lock()
        .unwrap()
        .open_binary(&root().join("tests/fixtures/ura64.exe"), None)
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let after = h
        .rpc(json!({"operation":"scripts","action":"list"}))
        .unwrap()["jobs"]
        .as_array()
        .unwrap()
        .len();
    assert_eq!(before, after);
}
