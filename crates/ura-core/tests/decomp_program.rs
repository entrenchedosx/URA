use std::path::Path;
use ura_core::decomp::{
    self, CallingConvention, DecompContext, Location, SignatureOverride, SignatureParameterInput,
    TypeRef,
};
use ura_core::{analyze_functions, AnalysisOptions};

fn chain(
    code: &[u8],
    configure: impl FnOnce(&mut DecompContext, u64),
) -> decomp::FunctionDecompilation {
    let mut bytes = include_bytes!("../../../tests/fixtures/ura64.exe").to_vec();
    let binary = ura_core::binary::analyze_bytes(Path::new("chain.exe"), bytes.clone()).unwrap();
    let entry = binary.analysis().entry_point.unwrap();
    let section = binary.analysis().section_containing_address(entry).unwrap();
    let offset = section.file_offset_for_address(entry).unwrap() as usize;
    bytes[offset..offset + 96].fill(0xcc);
    bytes[offset..offset + code.len()].copy_from_slice(code);
    let binary = ura_core::binary::analyze_bytes(Path::new("chain.exe"), bytes).unwrap();
    let analysis = analyze_functions(
        &binary,
        &AnalysisOptions {
            seed_symbols: false,
            ..Default::default()
        },
        &(),
    );
    let mut context = DecompContext::new(64);
    configure(&mut context, entry);
    decomp::analyze_function(&binary, &analysis, entry, &context, &()).unwrap()
}

fn hint(context: &mut DecompContext, address: u64, ty: TypeRef) {
    context.hints.insert(decomp::signature::describe_override(
        address,
        "known_sink",
        &SignatureOverride {
            convention: CallingConvention::Win64,
            return_type: TypeRef::Void,
            parameters: vec![SignatureParameterInput {
                name: "data".into(),
                location: Location::Register { name: "rcx".into() },
                ty,
            }],
            variadic: Some(false),
        },
    ));
}

fn wrappers() -> Vec<u8> {
    let mut code = vec![0xcc; 33];
    let wrapper = [
        0x48, 0x83, 0xec, 0x28, 0xe8, 7, 0, 0, 0, 0x48, 0x83, 0xc4, 0x28, 0xc3,
    ];
    code[..14].copy_from_slice(&wrapper);
    code[16..30].copy_from_slice(&wrapper);
    code[32] = 0xc3;
    code
}

#[test]
fn supplied_pointer_demand_reaches_two_callers_and_preserves_exact_sites() {
    let expected = TypeRef::pointer_to(TypeRef::uint(8), 64);
    let result = chain(&wrappers(), |context, entry| {
        hint(context, entry + 32, expected.clone())
    });
    assert_eq!(result.signature.parameters[0].ty, expected);
    assert!(result.program.converged);
    assert!(!result.program.truncated);
    assert_eq!(result.program.functions.len(), 3);
    assert_eq!(result.program.updates, 2);
    let sites: Vec<_> = result
        .program
        .edges
        .iter()
        .filter(|e| e.callee.register == "rcx")
        .map(|e| e.instruction.0)
        .collect();
    assert_eq!(sites, [result.function + 4, result.function + 20]);
    assert!(result
        .program
        .parameters
        .iter()
        .any(|p| p.parameter.function.0 == result.function
            && p.facts.claims[0].origin.function.0 == result.function + 32));
}

#[test]
fn unknown_call_cycles_do_not_invent_types() {
    let mut code = vec![0xcc; 22];
    code[..6].copy_from_slice(&[0xe8, 11, 0, 0, 0, 0xc3]);
    code[16..22].copy_from_slice(&[0xe8, 0xeb, 0xff, 0xff, 0xff, 0xc3]);
    let result = chain(&code, |_, _| {});
    assert!(result.program.converged);
    assert!(result.program.parameters.is_empty());
    assert_eq!(result.program.updates, 0);
    assert!(result.signature.parameters.is_empty());
}

#[test]
fn explicit_assertion_is_preserved_while_transitive_conflicts_remain_unknown() {
    let result = chain(&wrappers(), |context, entry| {
        hint(context, entry + 16, TypeRef::uint(64));
        hint(
            context,
            entry + 32,
            TypeRef::pointer_to(TypeRef::uint(8), 64),
        );
    });
    let facts = result
        .program
        .parameters
        .iter()
        .find(|p| p.parameter.function.0 == result.function)
        .unwrap();
    assert!(facts.facts.conflicting());
    assert!(matches!(
        result.signature.parameters[0].ty,
        TypeRef::Unknown { .. }
    ));
    assert!(!result.signature.conflicts.is_empty());
}

#[test]
fn call_clobbers_stop_entry_value_propagation() {
    // The second call receives unknown post-call state, not the original RCX.
    let mut code = vec![0xcc; 33];
    code[..11].copy_from_slice(&[0xe8, 11, 0, 0, 0, 0xe8, 22, 0, 0, 0, 0xc3]);
    code[16] = 0xc3;
    code[32] = 0xc3;
    let result = chain(&code, |context, entry| {
        hint(
            context,
            entry + 32,
            TypeRef::pointer_to(TypeRef::uint(8), 64),
        )
    });
    assert!(result
        .program
        .parameters
        .iter()
        .all(|p| p.parameter.function.0 != result.function));
    assert!(result.signature.parameters.is_empty());
}

#[test]
fn typed_tree_round_trip_keeps_operations_value_types_and_rendering() {
    let result = chain(&[0x48, 0x89, 0xc8, 0x48, 0x83, 0xc0, 3, 0xc3], |_, _| {});
    let ast = result.ast.unwrap();
    let encoded = serde_json::to_vec(&ast).unwrap();
    let decoded: decomp::HirFunction = serde_json::from_slice(&encoded).unwrap();
    let (rendered, truncated) = decomp::hir::render_ast(&decoded).unwrap();
    assert!(!truncated);
    assert_eq!(
        serde_json::to_value(rendered).unwrap(),
        serde_json::to_value(result.high_level.lines).unwrap()
    );
    let source = decoded.source.unwrap();
    assert_eq!(source.address_width, 64);
    assert!(source
        .blocks
        .iter()
        .flat_map(|b| &b.statements)
        .any(|s| s.op == ura_core::ir::Operation::Add));
    for statement in source.blocks.iter().flat_map(|b| &b.statements) {
        assert!(statement.source.0 >= result.function);
        if let Some(output) = statement.output {
            assert!(source.variables[output.variable].ty.valid());
        }
    }
}

#[test]
fn function_scope_budget_reports_partial_results_without_guessing() {
    let mut code = vec![0xcc; 18 * 16];
    for index in 0..17 {
        code[index * 16..index * 16 + 6].copy_from_slice(&[0xe8, 11, 0, 0, 0, 0xc3]);
    }
    code[17 * 16] = 0xc3;
    let result = chain(&code, |context, entry| {
        hint(context, entry + 17 * 16, TypeRef::uint(64))
    });
    assert!(result.program.converged);
    assert!(result.program.truncated);
    assert_eq!(
        result.program.functions.len(),
        decomp::program::MAX_FUNCTIONS
    );
    assert!(result.signature.parameters.is_empty());
    assert!(result
        .program
        .notes
        .iter()
        .any(|note| note.contains("complete binary")));
}

#[test]
fn actual_integer_argument_flows_forward_and_callee_return_flows_back() {
    let mut code = vec![0xcc; 36];
    code[..19].copy_from_slice(&[
        0xb9, 7, 0, 0, 0, 0x48, 0x83, 0xec, 0x28, 0xe8, 18, 0, 0, 0, 0x48, 0x83, 0xc4, 0x28, 0xc3,
    ]);
    code[32..36].copy_from_slice(&[0x48, 0x89, 0xc8, 0xc3]);
    let result = chain(&code, |_, _| {});
    let formal=result.program.flow.facts.iter().find(|result|matches!(&result.key,decomp::flow::Key::Parameter {function,register} if function.0==0x140001020 && register=="rcx")).unwrap();
    assert!(
        matches!(formal.facts.resolved(), Some(TypeRef::Int { bits: 64, .. })),
        "{formal:?}"
    );
    assert!(
        matches!(
            result.signature.return_value.ty,
            TypeRef::Int { bits: 64, .. }
        ),
        "{:?}",
        result.signature.return_value
    );
    assert!(result.program.flow.converged);
    assert!(result.program.flow.calls[0].return_value.is_some());
}

#[test]
fn exact_call_return_definition_receives_supplied_pointer_type() {
    let result = chain(
        &[0xe8, 0xfb, 0x0f, 0, 0, 0x48, 0x89, 0xc1, 0xc3],
        |context, entry| {
            context.hints.insert(decomp::signature::describe_override(
                entry + 0x1000,
                "supplied_external",
                &SignatureOverride {
                    convention: CallingConvention::Win64,
                    return_type: TypeRef::pointer_to(TypeRef::uint(8), 64),
                    parameters: vec![],
                    variadic: Some(false),
                },
            ));
        },
    );
    assert!(
        matches!(result.signature.return_value.ty, TypeRef::Pointer { .. }),
        "{:?}",
        result.signature.return_value
    );
    let returned = result.program.flow.calls[0].return_value.unwrap();
    let inferred = result
        .types
        .values
        .iter()
        .find(|ty| ty.value == returned)
        .unwrap();
    assert!(
        matches!(inferred.ty, TypeRef::Pointer { .. }),
        "{inferred:?}"
    );
    // The semantic operation remains unknown; type information never invents
    // a concrete value or removes the IR's register/memory clobbers.
    assert!(result
        .semantic
        .values
        .iter()
        .any(|value| value.ssa == returned
            && value.definition.is_some_and(|id| matches!(
                result.semantic.nodes[id].kind,
                decomp::semantic::NodeKind::UnknownEffect
            ))));
}

#[test]
fn caller_dereference_constrains_an_internal_return_without_fabricating_a_value() {
    let mut code = vec![0xcc; 36];
    code[..9].copy_from_slice(&[0xe8, 27, 0, 0, 0, 0x48, 0x8b, 0x10, 0xc3]);
    code[32..36].copy_from_slice(&[0x48, 0x89, 0xc8, 0xc3]);
    let result = chain(&code, |_, _| {});
    let returned=result.program.flow.facts.iter().find(|result|matches!(result.key,decomp::flow::Key::Return {function,..} if function.0==0x140001020)).unwrap();
    assert!(
        matches!(returned.facts.resolved(), Some(TypeRef::Pointer { .. })),
        "{returned:?}"
    );
    assert!(returned
        .facts
        .claims
        .iter()
        .any(|claim| claim.origin.0 == 0x140001000 && claim.instruction.is_some()));
}

#[test]
fn one_unestablished_return_path_remains_unknown() {
    // If RCX is zero, RET uses the incoming untouched RAX; the other path sets it.
    let result = chain(
        &[0x48, 0x85, 0xc9, 0x74, 5, 0xb8, 1, 0, 0, 0, 0xc3],
        |_, _| {},
    );
    assert!(matches!(
        result.signature.return_value.ty,
        TypeRef::Unknown { .. }
    ));
    assert!(result
        .program
        .flow
        .facts
        .iter()
        .any(|fact| matches!(fact.key, decomp::flow::Key::Return { .. }) && fact.facts.unknown));
}

#[test]
fn conflicting_supplied_caller_uses_are_not_silently_selected() {
    let result = chain(
        &[
            0xe8, 0xfb, 0x0f, 0, 0, 0x48, 0x89, 0xc1, 0xe8, 0xf3, 0x1f, 0, 0, 0xc3,
        ],
        |context, entry| {
            context.hints.insert(decomp::signature::describe_override(
                entry + 0x1000,
                "pointer_source",
                &SignatureOverride {
                    convention: CallingConvention::Win64,
                    return_type: TypeRef::pointer_to(TypeRef::uint(8), 64),
                    parameters: vec![],
                    variadic: Some(false),
                },
            ));
            hint(context, entry + 0x2000, TypeRef::uint(64));
        },
    );
    assert!(
        result
            .program
            .flow
            .facts
            .iter()
            .any(|result| result.facts.conflicting()),
        "{:?}",
        result.program.flow
    );
    assert!(result
        .types
        .values
        .iter()
        .any(|value| !value.conflicts.is_empty()));
}

#[test]
fn narrow_formal_does_not_falsely_type_or_conflict_the_whole_register() {
    let result = chain(
        &[0xb9, 7, 0, 0, 0, 0xe8, 0xf6, 0x0f, 0, 0, 0xc3],
        |context, entry| hint(context, entry + 0x1000, TypeRef::uint(32)),
    );
    let formal=result.program.flow.facts.iter().find(|result|matches!(&result.key,decomp::flow::Key::Parameter {function,register} if function.0==0x140002000 && register=="rcx")).unwrap();
    assert_eq!(formal.facts.resolved(), Some(TypeRef::uint(32)));
    assert!(!formal.facts.conflicting());
    assert!(result
        .program
        .flow
        .facts
        .iter()
        .filter(|result| result.key.function() == 0x140001000)
        .all(|result| !result.facts.conflicting()));
}

#[test]
fn void_call_result_cannot_become_a_known_pointer_from_a_dereference() {
    let result = chain(
        &[0xe8, 0xfb, 0x0f, 0, 0, 0x48, 0x8b, 0x08, 0xc3],
        |context, entry| {
            context.hints.insert(decomp::signature::describe_override(
                entry + 0x1000,
                "void_external",
                &SignatureOverride {
                    convention: CallingConvention::Win64,
                    return_type: TypeRef::Void,
                    parameters: vec![],
                    variadic: Some(false),
                },
            ));
        },
    );
    assert!(matches!(
        result.signature.return_value.ty,
        TypeRef::Unknown { .. }
    ));
    let returned = result.program.flow.calls[0].return_value.unwrap();
    assert!(matches!(
        result
            .types
            .values
            .iter()
            .find(|value| value.value == returned)
            .unwrap()
            .ty,
        TypeRef::Unknown { .. }
    ));
}
