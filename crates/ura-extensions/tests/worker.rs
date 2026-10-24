#![cfg(windows)]
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use ura_extensions::{runtime::Runtime, ExecutionConfig, ExtensionHost};
use ura_service::{PathPolicy, Service};
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn host() -> (ExtensionHost, String, tempfile::TempDir) {
    let folder = tempfile::tempdir().unwrap();
    let mut s = Service::new(PathPolicy::allow_all(), true);
    let h = s
        .open_binary(&root().join("tests/fixtures/ura64.exe"), None)
        .unwrap()
        .handle;
    s.analyze(&h, &Default::default()).unwrap();
    let config = ExecutionConfig {
        enabled: true,
        snippets: true,
        runtime: Some(Runtime::new(&root().join("target/python-runtime-3.14.9")).unwrap()),
        registry: folder.path().join("plugins"),
        ..Default::default()
    };
    (
        ExtensionHost::new(Arc::new(Mutex::new(s)), config).unwrap(),
        h,
        folder,
    )
}
fn run(h: &ExtensionHost, s: &str, code: &str, timeout: u64) -> Value {
    let job=h.rpc(json!({"operation":"scripts","action":"run","session":s,"code":code,"limits":{"timeoutMs":timeout}})).unwrap();
    let started = Instant::now();
    loop {
        let r = h.job(job["job"].as_str().unwrap()).unwrap();
        if r["state"] != "running" {
            return r;
        }
        assert!(started.elapsed() < Duration::from_secs(15), "{r}");
        std::thread::sleep(Duration::from_millis(10));
    }
}
#[test]
fn python_persists_real_engine_state_and_reports_exceptions() {
    let (h, handle, _folder) = host();
    let s = h
        .rpc(json!({"operation":"scripts","action":"open","handle":handle}))
        .unwrap();
    let s = s["session"].as_str().unwrap();
    let r=run(&h,s,"import ura\np=ura.current_project()\nf=next(p.functions())\nx=40\nprint(f.name, hex(f.address), p.read_bytes(f.address,1).hex())\nprint(len(f.cfg()['blocks']))\nprint(f.pseudocode())",30000);
    assert_eq!(r["state"], "complete", "{r}");
    assert!(r["stdout"].as_str().unwrap().contains("return"));
    assert_eq!(run(&h, s, "x+2", 30000)["stdout"], "42\n");
    let r = run(&h, s, "raise ValueError('expected')", 30000);
    assert_eq!(r["state"], "pythonError");
    assert!(r["error"].as_str().unwrap().contains("ValueError"));
    assert_eq!(run(&h, s, "x+3", 30000)["stdout"], "43\n");
}
#[test]
fn infinite_loop_is_terminated_and_new_interpreter_recovers() {
    let (h, handle, _folder) = host();
    let s = h
        .rpc(json!({"operation":"scripts","action":"open","handle":handle}))
        .unwrap();
    let r = run(&h, s["session"].as_str().unwrap(), "while True: pass", 100);
    assert_eq!(r["state"], "timeout", "{r}");
    h.rpc(json!({"operation":"scripts","action":"close","session":s["session"]}))
        .unwrap();
    let s = h
        .rpc(json!({"operation":"scripts","action":"open","handle":handle}))
        .unwrap();
    assert_eq!(
        run(
            &h,
            s["session"].as_str().unwrap(),
            "print('recovered')",
            30000
        )["stdout"],
        "recovered\n"
    );
}

#[test]
fn real_file_examples_and_content_pinning_work() {
    let folder = tempfile::tempdir().unwrap();
    let mut s = Service::new(PathPolicy::allow_all(), true);
    let handle = s
        .open_binary(&root().join("tests/fixtures/ura64.exe"), None)
        .unwrap()
        .handle;
    s.analyze(&handle, &Default::default()).unwrap();
    let inventory = root().join("sdk/examples/inventory.py");
    let report = root().join("sdk/examples/function_report.py");
    let mut c = ExecutionConfig {
        enabled: true,
        runtime: Some(Runtime::new(&root().join("target/python-runtime-3.14.9")).unwrap()),
        registry: folder.path().join("plugins"),
        ..Default::default()
    };
    c.trust_script(&inventory).unwrap();
    c.trust_script(&report).unwrap();
    let h = ExtensionHost::new(Arc::new(Mutex::new(s)), c).unwrap();
    let session = h
        .rpc(json!({"operation":"scripts","action":"open","handle":handle}))
        .unwrap();
    for path in [inventory, report] {
        let job=h.rpc(json!({"operation":"scripts","action":"run","session":session["session"],"path":path})).unwrap();
        let started = Instant::now();
        loop {
            let r = h.job(job["job"].as_str().unwrap()).unwrap();
            if r["state"] != "running" {
                assert_eq!(r["state"], "complete", "{r}");
                assert!(r["stdout"].as_str().unwrap().len() > 100);
                break;
            }
            assert!(started.elapsed() < Duration::from_secs(15));
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    assert!(h.rpc(json!({"operation":"scripts","action":"run","session":session["session"],"code":"print('denied')"})).is_err());
}

#[test]
fn worker_crash_output_memory_and_explicit_cancel_are_contained() {
    let (h, handle, _folder) = host();
    for (code, states) in [
        ("import os; os._exit(9)", vec!["crashed"]),
        ("print('x'*20000)", vec!["outputLimit"]),
        ("print('\\x00'*20000)", vec!["outputLimit"]),
        ("a=bytearray(512*1024*1024)", vec!["pythonError", "crashed"]),
    ] {
        let s = h
            .rpc(json!({"operation":"scripts","action":"open","handle":handle}))
            .unwrap();
        let limits = if code.starts_with("print") {
            json!({"outputBytes":1024})
        } else {
            json!({})
        };
        let j=h.rpc(json!({"operation":"scripts","action":"run","session":s["session"],"code":code,"limits":limits})).unwrap();
        let start = Instant::now();
        loop {
            let r = h.job(j["job"].as_str().unwrap()).unwrap();
            if r["state"] != "running" {
                assert!(states.contains(&r["state"].as_str().unwrap()), "{r}");
                break;
            }
            assert!(start.elapsed() < Duration::from_secs(15));
            std::thread::sleep(Duration::from_millis(10));
        }
        h.rpc(json!({"operation":"scripts","action":"close","session":s["session"]}))
            .unwrap();
    }
    let s = h
        .rpc(json!({"operation":"scripts","action":"open","handle":handle}))
        .unwrap();
    let j=h.rpc(json!({"operation":"scripts","action":"run","session":s["session"],"code":"while True: pass"})).unwrap();
    h.rpc(json!({"operation":"scripts","action":"cancel","job":j["job"]}))
        .unwrap();
    let start = Instant::now();
    loop {
        let r = h.job(j["job"].as_str().unwrap()).unwrap();
        if r["state"] != "running" {
            assert_eq!(r["state"], "cancelled", "{r}");
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn api_deadline_and_close_do_not_wait_for_busy_service() {
    let folder = tempfile::tempdir().unwrap();
    let mut s = Service::new(PathPolicy::allow_all(), false);
    let handle = s
        .open_binary(&root().join("tests/fixtures/ura64.exe"), None)
        .unwrap()
        .handle;
    s.analyze(&handle, &Default::default()).unwrap();
    let s = Arc::new(Mutex::new(s));
    let c = ExecutionConfig {
        enabled: true,
        snippets: true,
        runtime: Some(Runtime::new(&root().join("target/python-runtime-3.14.9")).unwrap()),
        registry: folder.path().join("plugins"),
        ..Default::default()
    };
    let h = ExtensionHost::new(s.clone(), c).unwrap();
    let session = h
        .rpc(json!({"operation":"scripts","action":"open","handle":handle}))
        .unwrap();
    let _lock = s.lock().unwrap();
    let start = Instant::now();
    let r = run(
        &h,
        session["session"].as_str().unwrap(),
        "import ura; ura.current_project().metadata()",
        100,
    );
    assert!(
        ["timeoutOrCancelled", "timeout"].contains(&r["state"].as_str().unwrap()),
        "{r}"
    );
    h.rpc(json!({"operation":"scripts","action":"close","session":session["session"]}))
        .unwrap();
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
fn blocked_protocol_input_cannot_defeat_deadline() {
    let folder = tempfile::tempdir().unwrap();
    let path = folder.path().join("nop.bin");
    std::fs::write(&path, vec![0x90; 8192]).unwrap();
    let mut s = Service::new(PathPolicy::allow_all(), false);
    let handle = s
        .open_raw_binary(&path, None, Some(0x1000), 64)
        .unwrap()
        .handle;
    let config = ExecutionConfig {
        enabled: true,
        snippets: true,
        runtime: Some(Runtime::new(&root().join("target/python-runtime-3.14.9")).unwrap()),
        registry: folder.path().join("plugins"),
        ..Default::default()
    };
    let h = ExtensionHost::new(Arc::new(Mutex::new(s)), config).unwrap();
    let session = h
        .rpc(json!({"operation":"scripts","action":"open","handle":handle}))
        .unwrap();
    let code="import os,json\nos.write(1,(json.dumps({'protocol':1,'kind':'call','id':42,'method':'instructions','params':{'address':'0x1000','limit':2000}})+'\\n').encode())\nwhile True: pass";
    let start = Instant::now();
    let r = run(&h, session["session"].as_str().unwrap(), code, 500);
    assert!(start.elapsed() < Duration::from_secs(3), "{r}");
    assert!(
        ["timeout", "timeoutOrCancelled"].contains(&r["state"].as_str().unwrap()),
        "{r}"
    );
    h.rpc(json!({"operation":"scripts","action":"close","session":session["session"]}))
        .unwrap();
}

#[test]
fn renamer_and_export_examples_use_real_permissions_and_persist() {
    let folder = tempfile::tempdir().unwrap();
    let project = folder.path().join("script.ura");
    let mut service = Service::new(PathPolicy::allow_all(), true);
    let handle = service
        .open_binary(&root().join("tests/fixtures/ura64.exe"), None)
        .unwrap()
        .handle;
    service.analyze(&handle, &Default::default()).unwrap();
    service
        .save_project(&handle, &project, Some("Python SDK"))
        .unwrap();
    let rename = root().join("sdk/examples/rename_functions.py");
    let export = root().join("sdk/examples/xref_export.py");
    let destination = folder.path().join("xrefs.json");
    let mut config = ExecutionConfig {
        enabled: true,
        runtime: Some(Runtime::new(&root().join("target/python-runtime-3.14.9")).unwrap()),
        registry: folder.path().join("plugins"),
        ..Default::default()
    };
    config
        .capabilities
        .extend(["project.write".into(), "files.export".into()]);
    config.trust_script(&rename).unwrap();
    config.trust_script(&export).unwrap();
    let caps = config.capabilities.clone();
    let h = ExtensionHost::new(Arc::new(Mutex::new(service)), config).unwrap();
    let session = h
        .rpc(json!({"operation":"scripts","action":"open","handle":handle,"capabilities":caps}))
        .unwrap();
    for (path, args) in [(rename, json!([])), (export, json!([destination]))] {
        let job=h.rpc(json!({"operation":"scripts","action":"run","session":session["session"],"path":path,"args":args})).unwrap();
        let start = Instant::now();
        loop {
            let r = h.job(job["job"].as_str().unwrap()).unwrap();
            if r["state"] != "running" {
                assert_eq!(r["state"], "complete", "{r}");
                break;
            }
            assert!(start.elapsed() < Duration::from_secs(15));
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    assert!(ura_project::read_project(&project)
        .unwrap()
        .function_names
        .iter()
        .any(|n| n.name.starts_with("reviewed_")));
    let data: Value = serde_json::from_slice(&std::fs::read(&destination).unwrap()).unwrap();
    assert!(!data.as_array().unwrap().is_empty());
}

#[test]
fn sdk_emulates_virtual_bytes_and_denies_project_writes_without_grant() {
    let folder = tempfile::tempdir().unwrap();
    let mut s = Service::new(PathPolicy::allow_all(), true);
    s.dynamic = ura_service::dynamic::DynamicService::new(PathPolicy::allow_all(), true)
        .with_emulation(true);
    let handle = s
        .open_binary(&root().join("tests/fixtures/ura64.exe"), None)
        .unwrap()
        .handle;
    s.analyze(&handle, &Default::default()).unwrap();
    let mut config = ExecutionConfig {
        enabled: true,
        snippets: true,
        runtime: Some(Runtime::new(&root().join("target/python-runtime-3.14.9")).unwrap()),
        registry: folder.path().join("plugins"),
        ..Default::default()
    };
    config.capabilities.insert("emulation.execute".into());
    let caps = config.capabilities.clone();
    let host = ExtensionHost::new(Arc::new(Mutex::new(s)), config).unwrap();
    let session = host
        .rpc(json!({"operation":"scripts","action":"open","handle":handle,"capabilities":caps}))
        .unwrap();
    let code="import ura\ne=ura.EmulationSession.create({'entry':'0x1000','mappings':[{'base':'0x1000','bytes':[184,42,0,0,0,195],'size':6,'permissions':{'read':True,'write':False,'execute':True}}]})\nprint(e.step(1))\nprint(e.memory(0x1000,1))\nprint(e.trace())\ne.close()\ntry:\n    ura.current_project().rename(0x140001020,'denied')\nexcept ura.UraError as error:\n    print(str(error))\nelse:\n    raise AssertionError('missing write grant accepted')";
    let r = run(&host, session["session"].as_str().unwrap(), code, 30000);
    assert_eq!(r["state"], "complete", "{r}");
    assert!(r["stdout"]
        .as_str()
        .unwrap()
        .contains("Permission denied: project.write"));
    assert!(r["stdout"].as_str().unwrap().contains("42"));
}
