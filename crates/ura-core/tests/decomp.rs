use std::path::{Path, PathBuf};

use ura_core::decomp::signature::{
    CallingConvention, Location, SignatureOverride, SignatureParameterInput,
};
use ura_core::decomp::{self, api, types::TypeRef, DecompContext};
use ura_core::{analyze_functions, analyze_path, LoadedBinary, ProgramAnalysis};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/ura64.exe")
}

fn analyzed() -> (LoadedBinary, ProgramAnalysis) {
    let binary = analyze_path(&fixture()).expect("fixture should parse");
    let analysis = analyze_functions(&binary, &Default::default(), &());
    (binary, analysis)
}

#[test]
fn recovers_entry_abi_stack_types_and_high_level_view() {
    let (binary, analysis) = analyzed();
    let context = DecompContext::new(64);
    let decompilation =
        decomp::analyze_function(&binary, &analysis, 0x140001020, &context, &()).unwrap();
    assert_eq!(decompilation.function, 0x140001020);
    assert_eq!(decompilation.signature.convention, CallingConvention::Win64);
    assert!(decompilation.signature.function == 0x140001020);
    assert_eq!(decompilation.high_level.status, "experimental-foundations");
    assert_eq!(decompilation.high_level.function, 0x140001020);
    let text = decompilation.high_level.text();
    assert!(text.contains("recovered high-level IR"));
    assert!(text.contains('{'));
    assert!(text.trim_end().ends_with('}'));
    assert_eq!(decompilation.frame.address_width, 64);
    assert!(!decompilation.high_level.lines.is_empty());
    assert!(decompilation
        .signature
        .declaration()
        .contains(&decompilation.name));
}

#[test]
fn call_graph_uses_direct_calls_and_bounds_path_queries() {
    let (_, analysis) = analyzed();
    let graph = decomp::build_call_graph(&analysis);
    assert!(graph.node(0x140001000).is_some());
    assert!(graph.node(0x140001020).is_some());
    assert!(graph
        .edges
        .iter()
        .any(|edge| edge.from == 0x140001000 && edge.to == 0x140001020 && edge.kind == "call"));
    assert!(graph.path_exists(0x140001000, 0x140001020, 8));
    assert!(!graph.path_exists(0x140001020, 0x140001000, 8));
    assert!(!graph.path_exists(0x140001000, 0x140001020, 0));
    assert!(graph
        .callees(0x140001000)
        .any(|edge| edge.to == 0x140001020));
    assert!(graph
        .callers(0x140001020)
        .any(|edge| edge.from == 0x140001000));
}

#[test]
fn user_override_replaces_inferred_signature_and_stack_names() {
    let (binary, analysis) = analyzed();
    let mut context = DecompContext::new(64);
    context.override_signature = Some(SignatureOverride {
        convention: CallingConvention::Win64,
        return_type: TypeRef::uint(64),
        parameters: vec![
            SignatureParameterInput {
                name: "count".into(),
                location: Location::Register { name: "rcx".into() },
                ty: TypeRef::uint(64),
            },
            SignatureParameterInput {
                name: "buffer".into(),
                location: Location::Register { name: "rdx".into() },
                ty: TypeRef::pointer_to(TypeRef::uint(8), 64),
            },
        ],
        variadic: Some(false),
    });
    let decompilation =
        decomp::analyze_function(&binary, &analysis, 0x140001020, &context, &()).unwrap();
    assert!(decompilation.signature.user_override);
    assert_eq!(decompilation.signature.parameters.len(), 2);
    assert_eq!(decompilation.signature.parameters[0].name, "count");
    assert_eq!(decompilation.signature.parameters[1].ty.display(), "u8*");
    assert!(decompilation.signature.declaration().starts_with("u64 "));

    let offset = decompilation
        .frame
        .slots
        .first()
        .map(|slot| slot.offset)
        .unwrap_or(-8);
    context.stack_overrides.insert(
        offset.to_string(),
        (Some("saved_counter".into()), Some(TypeRef::uint(32))),
    );
    let renamed = decomp::analyze_function(&binary, &analysis, 0x140001020, &context, &()).unwrap();
    let slot = renamed
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
}

#[test]
fn curated_api_database_rejects_unknown_names_and_builds_typed_signatures() {
    assert!(api::lookup("__imp_MessageBoxA").is_some());
    assert!(api::lookup("MessageBoxA@16").is_some());
    assert!(api::lookup("definitely_not_an_api").is_none());
    let prototype = api::lookup("memcpy").unwrap();
    let signature = api::instantiate(prototype, CallingConvention::Unknown, 64).unwrap();
    assert_eq!(signature.convention, CallingConvention::SysV64);
    assert_eq!(signature.parameters.len(), 3);
    assert_eq!(signature.parameters[0].location.display(), "rdi");
    let message_box = api::instantiate(
        api::lookup("MessageBoxA").unwrap(),
        CallingConvention::Win64,
        64,
    )
    .unwrap();
    assert_eq!(message_box.convention, CallingConvention::Win64);
    assert_eq!(message_box.parameters[3].location.display(), "r9");
    let names = api::names();
    assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
}
