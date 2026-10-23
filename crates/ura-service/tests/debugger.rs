#![cfg(all(windows, target_arch = "x86_64"))]
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use ura_service::{DebugPermissions, DebugService, PathPolicy};
#[path = "../../../tests/support/debug_fixture.rs"]
mod debug_fixture;
fn fixture() -> PathBuf {
    debug_fixture::fixture()
}

fn identity(path: &Path) -> ura_project::BinaryIdentity {
    let v = ura_core::analyze_path(path).unwrap().view();
    ura_project::BinaryIdentity {
        binary_path: v.path,
        binary_hash: v.sha256,
        file_size: v.file_size,
        format: v.format,
        architecture: v.architecture,
    }
}
#[test]
fn debugger_policy_persistence_cross_project_and_restore_rollback() {
    let target = fixture();
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("debug.ura");
    let target_identity = identity(&target);
    ura_project::create_project(&project, "debug", &target_identity).unwrap();
    let mut denied =
        DebugService::new(PathPolicy::allow_all(), DebugPermissions::default()).unwrap();
    assert!(denied
        .rpc(json!({"operation":"launch","executable":target}))
        .is_err());
    let mut service = DebugService::new(
        PathPolicy::new(vec![target.parent().unwrap().to_path_buf()]).unwrap(),
        DebugPermissions {
            launch: true,
            targets: vec![target.clone()],
            ..Default::default()
        },
    )
    .unwrap()
    .with_project_writes(true);
    service.grant_project(&project).unwrap();
    let launched = service
        .rpc(json!({"operation":"launch","executable":target}))
        .unwrap();
    let session = launched["session"].clone();
    let deadline = Instant::now() + Duration::from_secs(10);
    while service.snapshot().state != ura_debugger::State::Paused {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    let other = temp.path().join("other.ura");
    let other_sample = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/ura64.exe");
    let other_identity = identity(&other_sample);
    ura_project::create_project(&other, "other", &other_identity).unwrap();
    ura_project::save_debug_breakpoints(
        &other,
        &[ura_project::DebugBreakpoint {
            module_sha256: other_identity.binary_hash,
            rva: "0x1020".into(),
            enabled: true,
            ..Default::default()
        }],
    )
    .unwrap();
    service.grant_project(&other).unwrap();
    assert!(service
        .rpc(json!({"operation":"breakpoints","session":session,"action":"save","project":other}))
        .is_err());
    assert_eq!(
        ura_project::read_project(&other)
            .unwrap()
            .debug_breakpoints
            .len(),
        1
    );
    let binary = ura_core::analyze_path(&target).unwrap();
    let exports = binary.analysis().export_view_list();
    let marker = exports.iter().find(|e| e.name == "ura_marker").unwrap();
    let trap = exports
        .iter()
        .find(|e| e.name == "ura_existing_int3")
        .unwrap();
    let preferred = ura_core::parse_address(&binary.view().image_base).unwrap();
    let marker = ura_core::parse_address(&marker.address).unwrap() - preferred;
    let trap = ura_core::parse_address(&trap.address).unwrap() - preferred;
    ura_project::save_debug_breakpoints(
        &project,
        &[
            ura_project::DebugBreakpoint {
                module_sha256: target_identity.binary_hash.clone(),
                rva: ura_debugger::hex(marker),
                enabled: true,
                ..Default::default()
            },
            ura_project::DebugBreakpoint {
                module_sha256: target_identity.binary_hash,
                rva: ura_debugger::hex(trap),
                enabled: true,
                ..Default::default()
            },
        ],
    )
    .unwrap();
    let result = service.rpc(
        json!({"operation":"breakpoints","session":session,"action":"restore","project":project}),
    );
    assert!(result.is_err());
    assert!(
        service.snapshot().breakpoints.is_empty(),
        "first restored point must roll back when original INT3 rejects the second"
    );
    service
        .rpc(json!({"operation":"terminate","session":session}))
        .unwrap();
}
#[test]
fn advanced_rpc_permissions_atomic_exports_and_persistent_breakpoint_types() {
    let target = fixture();
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("advanced.ura");
    let id = identity(&target);
    ura_project::create_project(&project, "advanced", &id).unwrap();
    let mut service = DebugService::new(
        PathPolicy::allow_all(),
        DebugPermissions {
            launch: true,
            targets: vec![target.clone()],
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        service.rpc(json!({"operation":"capabilities"})).unwrap()["remote"],
        false
    );
    let mut session = service
        .rpc(json!({"operation":"launch","executable":target}))
        .unwrap()["session"]
        .clone();
    let deadline = Instant::now() + Duration::from_secs(10);
    while service.snapshot().state != ura_debugger::State::Paused {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    let image = ura_core::analyze_path(&target).unwrap();
    let base = ura_core::parse_address(&service.snapshot().modules[0].base).unwrap();
    let preferred = ura_core::parse_address(&image.view().image_base).unwrap();
    let runtime = |name: &str| {
        ura_debugger::hex(
            base + ura_core::parse_address(
                &image
                    .analysis()
                    .export_view_list()
                    .iter()
                    .find(|e| e.name == name)
                    .unwrap()
                    .address,
            )
            .unwrap()
                - preferred,
        )
    };
    let marker = runtime("ura_marker");
    let watched = runtime("ura_watch");
    assert!(service.rpc(json!({"operation":"snapshot","action":"capture","session":session,"address":marker,"length":32})).is_err());
    service = service.with_memory_capture(true);
    let capture=service.rpc(json!({"operation":"snapshot","action":"capture","session":session,"address":marker,"length":32})).unwrap();
    let capture_id = capture["id"].clone();
    assert!(service.rpc(json!({"operation":"snapshot","action":"export","session":session,"id":capture_id,"destination":dir.path().join("denied.json")})).is_err());
    service = service.with_project_writes(true);
    let destination = dir.path().join("capture.json");
    service.rpc(json!({"operation":"snapshot","action":"export","session":session,"id":capture_id,"destination":destination})).unwrap();
    let data = std::fs::read(&destination).unwrap();
    let imported: serde_json::Value = serde_json::from_slice(&data).unwrap();
    assert_eq!(imported, capture);
    assert!(service.rpc(json!({"operation":"snapshot","action":"export","session":session,"id":capture_id,"destination":destination})).is_err());
    assert_eq!(std::fs::read(destination).unwrap(), data);
    for (address, kind, length, condition) in [
        (marker.clone(), "software", 1, "ecx == 2"),
        (watched, "write", 8, "1"),
    ] {
        service.rpc(json!({"operation":"configureBreakpoint","session":session,"address":address,"kind":kind,"length":length,"condition":condition,"hitAfter":2,"hitEvery":3})).unwrap();
    }
    service
        .rpc(json!({"operation":"breakpoints","session":session,"action":"save","project":project}))
        .unwrap();
    let saved = ura_project::read_project(&project).unwrap();
    assert_eq!(saved.project.schema_version, 8);
    assert_eq!(saved.debug_breakpoints.len(), 2);
    assert!(saved
        .debug_breakpoints
        .iter()
        .any(|p| p.kind == "write" && p.length == 8));
    for point in service.snapshot().breakpoints {
        service.rpc(json!({"operation":"breakpoints","session":session,"action":"remove","id":point.id})).unwrap();
    }
    // A global hardware removal may retain physical slots on other threads until
    // their own event handoff. Restore into a fresh process (and ASLR base), not
    // over a still-retiring point in the current session.
    service
        .rpc(json!({"operation":"terminate","session":session}))
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while service.snapshot().state != ura_debugger::State::Exited {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    session = service
        .rpc(json!({"operation":"launch","executable":target}))
        .unwrap()["session"]
        .clone();
    while service.snapshot().state != ura_debugger::State::Paused {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    service.rpc(json!({"operation":"breakpoints","session":session,"action":"restore","project":project})).unwrap();
    let restored = service.snapshot();
    assert!(restored
        .breakpoints
        .iter()
        .any(|p| p.kind == ura_debugger::BreakpointKind::Write));
    assert!(restored
        .breakpoints
        .iter()
        .all(|p| p.hit_after == 2 && p.hit_every == 3 && p.hits == 0));
    service
        .rpc(json!({"operation":"terminate","session":session}))
        .unwrap();
}
