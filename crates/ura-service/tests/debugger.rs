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
            },
            ura_project::DebugBreakpoint {
                module_sha256: target_identity.binary_hash,
                rva: ura_debugger::hex(trap),
                enabled: true,
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
