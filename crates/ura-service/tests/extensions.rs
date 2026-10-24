use std::path::PathBuf;
use ura_project::scripting::MetadataEdit;
use ura_service::{PathPolicy, Service};
fn prepared() -> (Service, String, tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("test.ura");
    let mut s = Service::new(PathPolicy::allow_all(), true);
    let h = s
        .open_binary(
            &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/ura64.exe"),
            None,
        )
        .unwrap()
        .handle;
    s.analyze(&h, &Default::default()).unwrap();
    s.save_project(&h, &p, Some("Extensions")).unwrap();
    (s, h, d, p)
}
#[test]
fn metadata_transaction_rolls_back_and_persists_with_cas() {
    let (mut s, h, _d, p) = prepared();
    let identity = s.extension_identity(&h).unwrap();
    let original = ura_project::read_project(&p).unwrap();
    let bad = vec![
        MetadataEdit::Rename {
            address: "0x140001020".into(),
            name: "should_rollback".into(),
        },
        MetadataEdit::Comment {
            address: "0x140001020".into(),
            label: None,
            note: "x".repeat(16385),
        },
    ];
    assert!(s.extension_transaction(&h, &identity, &bad).is_err());
    assert_eq!(
        ura_project::read_project(&p).unwrap().function_names.len(),
        original.function_names.len()
    );
    assert_eq!(s.extension_identity(&h).unwrap(), identity);
    let valid = vec![
        MetadataEdit::Rename {
            address: "0x140001020".into(),
            name: "committed".into(),
        },
        MetadataEdit::Comment {
            address: "0x140001020".into(),
            label: Some("review".into()),
            note: "atomic".into(),
        },
    ];
    s.extension_transaction(&h, &identity, &valid).unwrap();
    let persisted = ura_project::read_project(&p).unwrap();
    assert!(persisted
        .function_names
        .iter()
        .any(|n| n.name == "committed"));
    assert!(persisted.annotations.iter().any(|a| a.note == "atomic"));
    assert!(s.extension_transaction(&h, &identity, &valid).is_err());
}
#[test]
fn external_metadata_change_invalidates_script_and_deleted_project_can_close() {
    let (mut s, h, _d, p) = prepared();
    let old = s.extension_identity(&h).unwrap();
    ura_project::save_annotation(&p, "0x140001020", None, "external").unwrap();
    assert_ne!(s.extension_identity(&h).unwrap(), old);
    std::fs::remove_file(&p).unwrap();
    s.close_binary(&h).unwrap();
    let (_, _, events) = s.events.page(0);
    let closed = events.iter().find(|e| e.kind == "project.closed").unwrap();
    assert!(closed.generation > 0);
    assert!(closed.data["binarySha256"].is_string());
}
#[test]
fn events_are_bounded_paged_ordered_and_report_gaps() {
    let bus = ura_service::events::EventBus::default();
    for i in 0..300 {
        bus.emit(
            "comment.changed",
            "bin1",
            1,
            None,
            serde_json::json!({"value":i,"huge":"x".repeat(17000)}),
        );
    }
    let (mut cursor, gap, page) = bus.page(0);
    assert!(gap);
    assert_eq!(page.len(), 32);
    assert_eq!(page[0].sequence, 45);
    assert_eq!(page[0].data["payloadOmitted"], true);
    let mut count = page.len();
    loop {
        let (next, _, page) = bus.page(cursor);
        if page.is_empty() {
            break;
        }
        assert!(page[0].sequence > cursor);
        cursor = next;
        count += page.len();
    }
    assert_eq!(count, 256);
}

#[test]
fn signatures_stack_types_and_type_library_share_atomic_transaction() {
    use ura_core::decomp::{
        signature::{CallingConvention, SignatureOverride},
        types::{TypeDatabase, TypeRef},
    };
    let (mut service, handle, _dir, project) = prepared();
    let signature = SignatureOverride {
        convention: CallingConvention::Win64,
        return_type: TypeRef::Int {
            bits: 32,
            signed: Some(false),
        },
        parameters: vec![],
        variadic: Some(false),
    };
    let edits = vec![
        MetadataEdit::Signature {
            address: "0x140001020".into(),
            signature,
        },
        MetadataEdit::StackVariable {
            address: "0x140001020".into(),
            offset: -8,
            name: Some("saved_value".into()),
            ty: Some(TypeRef::Int {
                bits: 64,
                signed: Some(false),
            }),
        },
        MetadataEdit::TypeLibrary {
            library: TypeDatabase::new(64),
        },
    ];
    let old = service.extension_identity(&handle).unwrap();
    service
        .extension_transaction(&handle, &old, &edits)
        .unwrap();
    let snapshot = ura_project::read_project(&project).unwrap();
    assert_eq!(snapshot.function_signatures.len(), 1);
    assert_eq!(
        snapshot.stack_variables[0].name.as_deref(),
        Some("saved_value")
    );
    assert_eq!(snapshot.type_library.unwrap().address_bits, 64);
    let current = service.extension_identity(&handle).unwrap();
    let bad = vec![
        MetadataEdit::Rename {
            address: "0x140001020".into(),
            name: "rollback_typed".into(),
        },
        MetadataEdit::StackVariable {
            address: "0x140001020".into(),
            offset: -8,
            name: Some("".into()),
            ty: None,
        },
    ];
    assert!(service
        .extension_transaction(&handle, &current, &bad)
        .is_err());
    assert_eq!(service.extension_identity(&handle).unwrap(), current);
    assert!(!ura_project::read_project(&project)
        .unwrap()
        .function_names
        .iter()
        .any(|n| n.name == "rollback_typed"));
}
