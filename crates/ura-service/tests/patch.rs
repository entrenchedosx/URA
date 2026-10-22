use ura_core::patch::Address;
use ura_service::{PathPolicy, Service, ServiceError};
fn fixture() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/ura64.exe")
}
#[test]
fn explicit_raw_mapping_persists_and_is_recovered_by_project_load() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("raw.bin");
    std::fs::write(&source, [0x90, 0x90, 0xc3]).unwrap();
    let project = dir.path().join("raw.ura");
    let mut service = Service::new(PathPolicy::allow_all(), true);
    let h = service
        .open_raw_binary(&source, None, Some(0x1000), 32)
        .unwrap()
        .handle;
    service.save_project(&h, &project, None).unwrap();
    let reopened = service.open_binary(&source, Some(&project)).unwrap().handle;
    let preview = service
        .preview_byte_patch(
            &reopened,
            Address::VirtualAddress(0x1000),
            &[0x90],
            &[0xc3],
            "",
        )
        .unwrap();
    service.apply_patch(&reopened, &project, &preview).unwrap();
    let out = dir.path().join("out.bin");
    service.export_patched_binary(&reopened, &out).unwrap();
    assert_eq!(std::fs::read(out).unwrap(), [0xc3, 0x90, 0xc3]);
    assert!(service
        .open_raw_binary(&source, Some(&project), Some(0x2000), 32)
        .is_err());
    let offset_only = service
        .open_raw_binary(&source, None, None, 64)
        .unwrap()
        .handle;
    assert!(service
        .read_effective_bytes(&offset_only, Address::VirtualAddress(0), 1)
        .is_err());
    assert!(service
        .read_effective_bytes(&offset_only, Address::FileOffset(0), 1)
        .is_ok());
}
#[test]
fn raw_and_executable_project_interpretations_cannot_be_mixed() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("sample.exe");
    std::fs::copy(fixture(), &source).unwrap();
    let project = dir.path().join("pe.ura");
    let mut s = Service::new(PathPolicy::allow_all(), true);
    let pe = s.open_binary(&source, None).unwrap().handle;
    s.save_project(&pe, &project, None).unwrap();
    assert!(s
        .open_raw_binary(&source, Some(&project), Some(0x1000), 64)
        .is_err());
    let raw = s
        .open_raw_binary(&source, None, Some(0x1000), 64)
        .unwrap()
        .handle;
    assert!(s.save_project(&raw, &project, None).is_err());
    let state = s.list_patches(&raw).unwrap().state;
    assert!(ura_project::save_patch_state(&project, &state, 0).is_err());
    assert!(s.open_binary(&source, Some(&project)).is_ok());
}
#[test]
fn patch_project_reopen_export_and_all_derived_analysis_use_effective_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("sample.exe");
    std::fs::copy(fixture(), &source).unwrap();
    let original = std::fs::read(&source).unwrap();
    let project = dir.path().join("project.ura");
    let mut service = Service::new(PathPolicy::new([dir.path().to_path_buf()]).unwrap(), true);
    let handle = service.open_binary(&source, None).unwrap().handle;
    service.save_project(&handle, &project, None).unwrap();
    service.analyze(&handle, &Default::default()).unwrap();
    let old = service
        .decompile(&handle, "140001020", 0, 200, false)
        .unwrap();
    let preview = service
        .preview_instruction_patch(
            &handle,
            Address::VirtualAddress(0x140001020),
            1,
            "ret",
            false,
            "",
        )
        .unwrap();
    let applied = service
        .apply_patch(&handle, &project, &preview.patch)
        .unwrap();
    assert!(!applied.analysis_current);
    assert_eq!(applied.changed_bytes, 1);
    assert!(matches!(
        service.decompile(&handle, "140001020", 0, 200, false),
        Err(ServiceError::AnalysisRequired)
    ));
    service.analyze(&handle, &Default::default()).unwrap();
    let new = service
        .decompile(&handle, "140001020", 0, 200, false)
        .unwrap();
    assert!(new.total < old.total);
    let reopened = service.open_binary(&source, Some(&project)).unwrap().handle;
    assert_eq!(
        service
            .read_effective_bytes(&reopened, Address::VirtualAddress(0x140001020), 1)
            .unwrap()
            .current,
        [0xc3]
    );
    let out = dir.path().join("patched.exe");
    let exported = service.export_patched_binary(&reopened, &out).unwrap();
    assert_eq!(
        exported.sha256,
        ura_core::sha256_hex(&std::fs::read(&out).unwrap())
    );
    let actual = std::fs::read(&out).unwrap();
    assert_eq!(actual.len(), original.len());
    assert_eq!(&actual[..0x220], &original[..0x220]);
    assert_eq!(&actual[0x221..], &original[0x221..]);
    assert_eq!(std::fs::read(&source).unwrap(), original);
    service
        .patch_history(&reopened, &project, "undo", None)
        .unwrap();
    service
        .patch_history(&reopened, &project, "redo", None)
        .unwrap();
    assert!(service.export_patched_binary(&reopened, &out).is_err());
}
#[test]
fn saving_as_and_attaching_projects_preserves_each_history_and_allows_next_edit() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("sample.exe");
    std::fs::copy(fixture(), &source).unwrap();
    let p = dir.path().join("p.ura");
    let q = dir.path().join("q.ura");
    let mut s = Service::new(PathPolicy::allow_all(), true);
    let h = s.open_binary(&source, None).unwrap().handle;
    s.save_project(&h, &p, None).unwrap();
    let a = Address::VirtualAddress(0x140001020);
    let preview = s.preview_byte_patch(&h, a, &[0x55], &[0xc3], "").unwrap();
    s.apply_patch(&h, &p, &preview).unwrap();
    s.save_project(&h, &q, None).unwrap();
    let h2 = s.open_binary(&source, Some(&q)).unwrap().handle;
    assert_eq!(s.read_effective_bytes(&h2, a, 1).unwrap().current, [0xc3]);
    let preview = s.preview_byte_patch(&h, a, &[0xc3], &[0x90], "").unwrap();
    s.apply_patch(&h, &q, &preview).unwrap();
    s.save_project(&h, &p, None).unwrap();
    assert_eq!(s.read_effective_bytes(&h, a, 1).unwrap().current, [0xc3]);
    assert_eq!(s.list_patches(&h).unwrap().state.cursor, 1);
    let preview = s.preview_byte_patch(&h, a, &[0xc3], &[0x90], "").unwrap();
    s.apply_patch(&h, &p, &preview).unwrap();
}
#[test]
fn read_only_path_project_and_stale_revision_checks_leave_state_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("sample.exe");
    std::fs::copy(fixture(), &source).unwrap();
    let p = dir.path().join("p.ura");
    let mut writer = Service::new(PathPolicy::new([dir.path().to_path_buf()]).unwrap(), true);
    let h = writer.open_binary(&source, None).unwrap().handle;
    writer.save_project(&h, &p, None).unwrap();
    let mut reader = Service::new(PathPolicy::new([dir.path().to_path_buf()]).unwrap(), false);
    let r = reader.open_binary(&source, Some(&p)).unwrap().handle;
    let a = Address::FileOffset(0x220);
    let preview = reader
        .preview_byte_patch(&r, a, &[0x55], &[0xc3], "")
        .unwrap();
    assert!(matches!(
        reader.apply_patch(&r, &p, &preview),
        Err(ServiceError::WriteDisabled)
    ));
    assert!(matches!(
        reader.export_patched_binary(&r, &dir.path().join("denied.exe")),
        Err(ServiceError::WriteDisabled)
    ));
    let stale = writer.open_binary(&source, Some(&p)).unwrap().handle;
    writer.apply_patch(&h, &p, &preview).unwrap();
    let before = writer.list_patches(&stale).unwrap().state;
    assert!(writer.apply_patch(&stale, &p, &preview).is_err());
    assert_eq!(writer.list_patches(&stale).unwrap().state, before);
    assert!(writer
        .apply_patch(&h, &dir.path().join("different.ura"), &preview)
        .is_err());
    let outside = tempfile::tempdir().unwrap();
    assert!(matches!(
        writer.export_patched_binary(&h, &outside.path().join("denied.exe")),
        Err(ServiceError::PathDenied(_))
    ));
}
