use serde_json::{json, Value};
use std::{
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};
use ura_service::{dynamic::DynamicService, PathPolicy};
fn create(service: &mut DynamicService, code: &[u8]) -> String {
    service.rpc(json!({"operation":"emulation","action":"create","config":{"entry":"0x1000","mappings":[{"base":"0x1000","bytes":code,"size":code.len(),"permissions":{"read":true,"write":false,"execute":true}}]}})).unwrap()["session"].as_str().unwrap().into()
}
fn wait(service: &mut DynamicService, session: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let v = service
            .rpc(json!({"operation":"emulation","action":"status","session":session}))
            .unwrap();
        if v["busy"] == false {
            return v;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(1));
    }
}
#[test]
fn emulation_permissions_async_cancel_session_limits_and_stale_handles() {
    let mut service = DynamicService::new(PathPolicy::allow_all(), false);
    assert!(service
        .rpc(json!({"operation":"emulation","action":"create"}))
        .is_err());
    let mut service = service.with_emulation(true);
    let id = create(&mut service, &[0xeb, 0xfe]);
    service
        .rpc(json!({"operation":"emulation","action":"run","session":id,"steps":1000000}))
        .unwrap();
    let start = Instant::now();
    service
        .rpc(json!({"operation":"emulation","action":"stop","session":id}))
        .unwrap();
    let state = wait(&mut service, &id);
    assert!(start.elapsed() < Duration::from_secs(1));
    assert_eq!(state["state"]["stopReason"], "cancelled");
    for _ in 0..3 {
        create(&mut service, &[0xc3]);
    }
    assert!(service
        .rpc(json!({"operation":"emulation","action":"create"}))
        .is_err());
    service
        .rpc(json!({"operation":"emulation","action":"close","session":id}))
        .unwrap();
    assert!(service
        .rpc(json!({"operation":"emulation","action":"status","session":id}))
        .is_err());
}
#[test]
fn real_virtual_execution_export_replay_image_and_no_clobber() {
    let dir = tempfile::tempdir().unwrap();
    let mut service =
        DynamicService::new(PathPolicy::new([dir.path().to_path_buf()]).unwrap(), true)
            .with_emulation(true);
    let id = create(&mut service, &[0xb8, 42, 0, 0, 0, 0xc3]);
    service
        .rpc(json!({"operation":"emulation","action":"run","session":id,"steps":10}))
        .unwrap();
    let state = wait(&mut service, &id);
    assert_eq!(state["state"]["registers"]["rax"], "0x2A");
    let path = dir.path().join("trace.json");
    let receipt = service
        .rpc(
            json!({"operation":"emulation","action":"exportTrace","session":id,"destination":path}),
        )
        .unwrap();
    let before = std::fs::read(&path).unwrap();
    assert_eq!(receipt["sha256"], ura_core::sha256_hex(&before));
    assert!(service
        .rpc(
            json!({"operation":"emulation","action":"exportTrace","session":id,"destination":path})
        )
        .is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let replay = service
        .rpc(json!({"operation":"replay","action":"open","path":path}))
        .unwrap()["handle"]
        .clone();
    let observed = service
        .rpc(json!({"operation":"replay","action":"state","handle":replay,"index":0}))
        .unwrap();
    assert_eq!(observed["registers"]["rax"], "0x2A");
    assert_eq!(observed["memoryAvailable"], false);
    let image = service
        .rpc(json!({"operation":"emulation","action":"memoryImage","session":id}))
        .unwrap()["handle"]
        .clone();
    let analyzed = service
        .rpc(json!({"operation":"image","action":"analyze","handle":image,"entry":"0x1000"}))
        .unwrap();
    assert!(analyzed["pseudocode"].is_object());
    let path = dir.path().join("image.json");
    service
        .rpc(json!({"operation":"image","action":"export","handle":image,"destination":path}))
        .unwrap();
    let reimport = service
        .rpc(json!({"operation":"image","action":"open","path":path}))
        .unwrap()["handle"]
        .clone();
    let compare=service.rpc(json!({"operation":"image","action":"compare","handle":image,"other":reimport,"address":"0x1000","length":6})).unwrap();
    assert_eq!(compare["changedBytes"], 0);
    assert_eq!(compare["unknownBytes"], 0);
    let other = create(&mut service, &[0x90, 0xc3]);
    let state = service
        .rpc(json!({"operation":"emulation","action":"status","session":other}))
        .unwrap();
    assert_eq!(state["state"]["instructions"], 0);
}
#[test]
fn read_only_evidence_has_no_execution_or_output_grant_and_paths_are_checked() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let input = outside.path().join("trace.json");
    std::fs::write(&input, b"{}").unwrap();
    let mut service =
        DynamicService::new(PathPolicy::new([root.path().to_path_buf()]).unwrap(), false)
            .with_emulation(true);
    assert!(service
        .rpc(json!({"operation":"replay","action":"open","path":input}))
        .is_err());
    let id = create(&mut service, &[0xc3]);
    assert!(service.rpc(json!({"operation":"emulation","action":"exportTrace","session":id,"destination":root.path().join("denied.json")})).is_err());
    assert!(!root.path().join("denied.json").exists());
    assert!(service
        .rpc(json!({"operation":"emulation","action":"run","session":id,"steps":1000001}))
        .is_err());
    let _ = AtomicBool::new(false);
}

#[test]
fn checkpoint_mutations_refresh_status_without_running() {
    let mut service = DynamicService::new(PathPolicy::allow_all(), false).with_emulation(true);
    let session = create(&mut service, &[0xc3]);
    let id = service
        .rpc(json!({"operation":"emulation","action":"snapshot","session":session}))
        .unwrap()["id"]
        .clone();
    assert_eq!(wait(&mut service, &session)["state"]["snapshots"], 1);
    service
        .rpc(json!({"operation":"emulation","action":"removeSnapshot","session":session,"id":id}))
        .unwrap();
    assert_eq!(wait(&mut service, &session)["state"]["snapshots"], 0);
}

#[test]
fn virtual_decode_and_explicit_legacy_capture_architecture() {
    let directory = tempfile::tempdir().unwrap();
    let mut service = DynamicService::new(
        PathPolicy::new([directory.path().to_path_buf()]).unwrap(),
        false,
    )
    .with_emulation(true);
    let session = create(&mut service, &[0xb8, 42, 0, 0, 0, 0xc3]);
    let decoded=service.rpc(json!({"operation":"emulation","action":"disassembly","session":session,"address":"0x1000"})).unwrap();
    assert_eq!(decoded["mode"], "emulated");
    assert_eq!(decoded["instructions"][0]["address"], "0x1000");
    let bytes = vec![0xc3];
    let path = directory.path().join("snapshot.json");
    std::fs::write(&path,serde_json::to_vec(&json!({"format":"ura-memory-snapshot","schemaVersion":1,"address":"0x1000","requested":1,"captured":1,"missing":0,"capturedBytesSha256":ura_core::sha256_hex(&bytes),"chunks":[{"address":"0x1000","requested":1,"bytes":bytes,"missing":0,"region":{"protection":32}}]})).unwrap()).unwrap();
    let image = service
        .rpc(json!({"operation":"image","action":"open","path":path,"bitness":32}))
        .unwrap();
    assert_eq!(image["info"]["bitness"], 32);
    assert!(image["info"]["provenance"]
        .as_str()
        .unwrap()
        .contains("explicit analyst assumption"));
}
