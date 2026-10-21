use std::path::{Path, PathBuf};

use ura_core::decomp::signature::{
    CallingConvention, Location, SignatureOverride, SignatureParameterInput,
};
use ura_core::decomp::types::TypeRef;
use ura_core::AnalysisOptions;
use ura_service::{PathPolicy, Service};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/ura64.exe")
}

fn analyzed(service: &mut Service) -> String {
    let handle = service.open_binary(&fixture(), None).unwrap().handle;
    service
        .analyze(&handle, &AnalysisOptions::default())
        .unwrap();
    handle
}

#[test]
fn exposes_signature_stack_types_high_level_and_call_graph_views() {
    let mut service = Service::new(PathPolicy::allow_all(), false);
    let handle = analyzed(&mut service);
    let signature = service.function_signature(&handle, "140001020").unwrap();
    assert_eq!(signature.schema_version, 1);
    assert_eq!(signature.function, "0x140001020");
    assert_eq!(signature.signature.convention, CallingConvention::Win64);
    assert!(signature.signature.declaration().contains(&signature.name));
    assert!(!signature.binary_hash.is_empty());

    let stack = service.stack_frame(&handle, "140001020").unwrap();
    assert_eq!(stack.frame.address_width, 64);
    assert_eq!(stack.function, "0x140001020");
    let types = service.inferred_types(&handle, "140001020").unwrap();
    assert_eq!(types.function, "0x140001020");
    assert!(types.database_errors.is_empty());
    assert!(!types.types.notes.is_empty());

    let high = service.high_level(&handle, "140001020", 0, 20).unwrap();
    assert_eq!(high.status, "experimental-foundations");
    assert!(high.total > 0);
    assert!(high.returned <= 20);
    assert_eq!(high.function, "0x140001020");
    assert!(high.lines.iter().any(|line| line.kind == "signature"));
    assert_eq!(
        service
            .high_level(&handle, "140001020", 0, 2_001)
            .unwrap_err()
            .code(),
        "limit_exceeded"
    );

    let graph = service
        .call_graph(&handle, Some("0x140001000"), 1, 100)
        .unwrap();
    assert_eq!(graph.focus.as_deref(), Some("0x140001000"));
    assert!(graph.nodes.iter().any(|node| node.address == "0x140001020"));
    assert!(graph
        .edges
        .iter()
        .any(|edge| edge.from == "0x140001000" && edge.to == "0x140001020"));
    assert!(graph.truncated || graph.returned_nodes <= graph.total_nodes);
    assert_eq!(
        service
            .call_graph(&handle, None, 17, 100)
            .unwrap_err()
            .code(),
        "limit_exceeded"
    );
    assert_eq!(
        service
            .call_graph(&handle, Some("0x1"), 1, 100)
            .unwrap_err()
            .code(),
        "function_not_found"
    );
}

#[test]
fn persists_signature_and_stack_variable_overrides_across_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let project_path = directory.path().join("decomp.ura");
    let mut service = Service::new(PathPolicy::allow_all(), true);
    let handle = analyzed(&mut service);
    service
        .save_project(&handle, &project_path, Some("Decompiler"))
        .unwrap();
    let offset = service
        .stack_frame(&handle, "140001020")
        .unwrap()
        .frame
        .slots
        .first()
        .map(|slot| slot.offset)
        .unwrap_or(-8);
    let signature = SignatureOverride {
        convention: CallingConvention::Win64,
        return_type: TypeRef::uint(64),
        parameters: vec![SignatureParameterInput {
            name: "count".into(),
            location: Location::Register { name: "rcx".into() },
            ty: TypeRef::uint(64),
        }],
        variadic: Some(false),
    };
    let applied = service
        .set_function_signature(&handle, &project_path, "140001020", &signature)
        .unwrap();
    assert!(applied.signature.user_override);
    assert_eq!(applied.signature.parameters[0].name, "count");

    let variable = service
        .set_stack_variable(
            &handle,
            &project_path,
            "140001020",
            offset,
            Some("saved_counter"),
            Some(&TypeRef::uint(32)),
        )
        .unwrap();
    assert!(!variable.removed);
    assert_eq!(
        variable.variable.as_ref().map(|entry| entry.offset),
        Some(offset)
    );
    let slot = variable
        .frame
        .slots
        .iter()
        .find(|slot| slot.offset == offset)
        .unwrap();
    assert_eq!(slot.user_name.as_deref(), Some("saved_counter"));
    assert_eq!(
        slot.user_type.as_ref().map(TypeRef::display),
        Some("u32".into())
    );
    assert_eq!(
        service
            .set_stack_variable(
                &handle,
                &project_path,
                "140001020",
                0x7fff_ffff,
                Some("bad"),
                None,
            )
            .unwrap_err()
            .code(),
        "invalid_argument"
    );
    service.close_binary(&handle).unwrap();

    let mut reopened = Service::new(PathPolicy::allow_all(), true);
    let handle = reopened
        .open_binary(&fixture(), Some(&project_path))
        .unwrap()
        .handle;
    reopened
        .analyze(&handle, &AnalysisOptions::default())
        .unwrap();
    let signature = reopened.function_signature(&handle, "140001020").unwrap();
    assert!(signature.signature.user_override);
    assert_eq!(signature.signature.parameters[0].name, "count");
    let stack = reopened.stack_frame(&handle, "140001020").unwrap();
    let slot = stack
        .frame
        .slots
        .iter()
        .find(|slot| slot.offset == offset)
        .unwrap();
    assert_eq!(slot.user_name.as_deref(), Some("saved_counter"));

    let cleared = reopened
        .set_stack_variable(&handle, &project_path, "140001020", offset, None, None)
        .unwrap();
    assert!(cleared.removed);
    assert!(cleared.variable.is_none());
    let slot = cleared
        .frame
        .slots
        .iter()
        .find(|slot| slot.offset == offset)
        .unwrap();
    assert!(slot.user_name.is_none());
}

#[test]
fn overrides_require_writes_and_an_attached_matching_project() {
    let directory = tempfile::tempdir().unwrap();
    let project_path = directory.path().join("writes.ura");
    let mut service = Service::new(PathPolicy::allow_all(), false);
    let handle = analyzed(&mut service);
    let signature = SignatureOverride {
        convention: CallingConvention::Win64,
        return_type: TypeRef::uint(64),
        parameters: vec![],
        variadic: None,
    };
    assert_eq!(
        service
            .set_function_signature(&handle, &project_path, "140001020", &signature)
            .unwrap_err()
            .code(),
        "write_disabled"
    );

    let mut service = Service::new(PathPolicy::allow_all(), true);
    let handle = analyzed(&mut service);
    assert_eq!(
        service
            .set_function_signature(&handle, &project_path, "140001020", &signature)
            .unwrap_err()
            .code(),
        "project_not_found"
    );
    service
        .save_project(&handle, &project_path, Some("Writes"))
        .unwrap();
    let mut invalid = signature.clone();
    invalid.parameters = vec![SignatureParameterInput {
        name: "bad name".into(),
        location: Location::Unknown {
            reason: "test".into(),
        },
        ty: TypeRef::uint(8),
    }];
    assert_eq!(
        service
            .set_function_signature(&handle, &project_path, "140001020", &invalid)
            .unwrap_err()
            .code(),
        "invalid_argument"
    );
    assert!(service
        .set_function_signature(&handle, &project_path, "140001020", &signature)
        .is_ok());
}
