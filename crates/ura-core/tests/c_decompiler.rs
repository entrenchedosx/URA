use std::collections::BTreeMap;
use ura_core::{
    decomp::{
        semantic,
        source::{
            self,
            evaluate::{Exit, State},
            *,
        },
        types,
    },
    ir::{self, ssa, Address, Constant, Type},
    AnalysisOptions, CodeImage, CodeRegion,
};

fn variable(id: usize, width: u16) -> Variable {
    Variable {
        id,
        name: format!("v{id}"),
        storage: Type::Bits(width),
        inferred_type: types::TypeRef::int(width),
        ssa: None,
        entry_register: Some(format!("r{id}")),
        parameter: None,
        scratch: false,
    }
}
fn function(variables: Vec<Variable>, body: Vec<Statement>) -> Function {
    Function {
        version: VERSION,
        address: Address(0x1000),
        name: "fixture".into(),
        address_width: 64,
        signature: None,
        variables,
        body,
        sources: Vec::new(),
        diagnostics: Vec::new(),
        unresolved: 0,
        truncated: false,
        types_partial: false,
        eliminated_temporaries: 0,
        phi_copies: 0,
    }
}
fn statement(kind: StatementKind) -> Statement {
    Statement {
        source: None,
        synthetic: true,
        kind,
    }
}
fn constant(width: u16, value: u64) -> Expr {
    Expr {
        storage: Type::Bits(width),
        source: None,
        kind: ExprKind::Constant {
            constant: Constant::bits(width, value),
        },
    }
}
fn reconstruct(code: &[u8]) -> Output {
    let hir = semantic_function(code);
    source::build(&hir, "test_function", &Default::default(), None, &()).unwrap()
}
fn semantic_function(code: &[u8]) -> semantic::SemanticFunction {
    let image = CodeImage::new(vec![CodeRegion {
        start: 0x1000,
        bytes: code,
    }]);
    let analysis = ura_core::analyze_image(
        &image,
        64,
        Some(0x1000),
        &[],
        &AnalysisOptions::default(),
        &(),
    );
    let raw = ir::lift_image(&image, 64, &analysis, 0x1000, &()).unwrap();
    let ssa = ssa::construct(&raw).unwrap();
    let (types, _) = types::infer_ssa_types(&ssa, &()).unwrap();
    semantic::lower(&ssa, &types, &()).unwrap()
}

fn signature(address: u64, names: &[(&str, &str, u16)]) -> ura_core::decomp::FunctionSignature {
    use ura_core::decomp::{signature::*, TypeRef};
    describe_override(
        address,
        "known",
        &SignatureOverride {
            convention: CallingConvention::Win64,
            return_type: TypeRef::int(64),
            parameters: names
                .iter()
                .map(|(name, register, width)| SignatureParameterInput {
                    name: (*name).into(),
                    location: Location::Register {
                        name: (*register).into(),
                    },
                    ty: TypeRef::Int {
                        bits: *width,
                        signed: Some(true),
                    },
                })
                .collect(),
            variadic: Some(false),
        },
    )
}

#[test]
fn signed_formals_use_unsigned_machine_operands_and_names_are_unique() {
    // cmp rcx,rdx; setb al; movzx eax,al; ret. Build the comparison directly
    // because SETcc is deliberately outside the current native lifter subset.
    let mut hir = semantic_function(&[0x48, 0x89, 0xc8, 0x48, 0x29, 0xd0, 0xc3]);
    hir.attach_signature(&signature(
        0x1000,
        &[("x_2", "rcx", 64), ("x", "rdx", 64), ("x", "r8", 64)],
    ));
    let output = source::build(&hir, "signed", &Default::default(), None, &()).unwrap();
    assert!(output.text().contains("((uint64_t)x_2)"));
    assert!(output.text().contains("((uint64_t)x)"));
    let names: std::collections::BTreeSet<_> =
        output.ast.variables.iter().map(|v| &v.name).collect();
    assert_eq!(names.len(), output.ast.variables.len());
    let params = &output.ast.signature.as_ref().unwrap().parameters;
    assert_eq!(
        params
            .iter()
            .map(|p| &p.name)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        3
    );
}

#[test]
fn narrow_entry_parameters_use_only_proved_low_bits() {
    let mut hir = semantic_function(&[0x89, 0xc8, 0xc3]); // mov eax,ecx; ret
    let mut sig = signature(0x1000, &[("count", "rcx", 32)]);
    sig.return_value.ty = types::TypeRef::int(32);
    hir.attach_signature(&sig);
    let output = source::build(&hir, "narrow", &Default::default(), None, &()).unwrap();
    assert!(
        output.text().contains("((uint32_t)count)"),
        "{}",
        output.text()
    );
    let mut state = State::default();
    state.registers = BTreeMap::from([
        ("rcx".into(), 0xffff_ffff_1234_5678),
        ("rsp".into(), 0x8000),
    ]);
    for i in 0..8 {
        state.memory.insert(0x8000 + i, 0);
    }
    assert_eq!(
        state.run(&output.ast, 1000).unwrap(),
        Exit::Return {
            result: Some(0x1234_5678),
            destination: Some(0)
        }
    );
}

#[test]
fn overwritten_entry_register_is_recovered_as_a_known_call_argument() {
    let hir = semantic_function(&[0xb9, 1, 0, 0, 0, 0xe8, 0xf6, 0x0f, 0, 0, 0xc3]); // call 0x2000
    let mut hints = ura_core::decomp::SignatureHints::default();
    hints.insert(signature(0x2000, &[("arg", "rcx", 64)]));
    let output = source::build(&hir, "caller", &hints, None, &()).unwrap();
    let call = output
        .ast
        .body
        .iter()
        .find_map(|s| {
            if let StatementKind::Call {
                arguments,
                unknown_arguments,
                ..
            } = &s.kind
            {
                Some((arguments, *unknown_arguments))
            } else {
                None
            }
        })
        .unwrap();
    assert!(!call.1);
    assert_eq!(call.0.len(), 1);
    assert!(!matches!(call.0[0].kind, ExprKind::Unknown { .. }));
}

#[test]
fn unsupported_call_formals_and_non_native_pointer_widths_stay_explicit() {
    let mut hir = semantic_function(&[0xb9, 1, 0, 0, 0, 0xe8, 0xf6, 0x0f, 0, 0, 0xc3]);
    let mut callee = signature(0x2000, &[("arg", "rcx", 64)]);
    callee.parameters[0].ty = types::TypeRef::Float { bits: 64 };
    let mut hints = ura_core::decomp::SignatureHints::default();
    hints.insert(callee);
    let output = source::build(&hir, "caller", &hints, None, &()).unwrap();
    assert!(output.ast.body.iter().any(|s| matches!(
        s.kind,
        StatementKind::Call {
            unknown_arguments: true,
            ..
        }
    )));
    let mut sig = signature(0x1000, &[("small_pointer", "rcx", 32)]);
    sig.parameters[0].ty = types::TypeRef::Pointer {
        to: Box::new(types::TypeRef::int(8)),
        address_bits: 32,
    };
    hir.attach_signature(&sig);
    let output = source::build(&hir, "pointer", &hints, None, &()).unwrap();
    assert!(output.text().contains("ura_ptr32_t"));
}

#[test]
fn backward_call_snapshot_keeps_its_definition_and_jump_provenance() {
    // Entry jumps over a call block. The defining block has a store plus the
    // call snapshot use; a store-only count incorrectly removed the assignment.
    let mut code = vec![0x90; 0x2d];
    code[0..2].copy_from_slice(&[0xeb, 0x1e]);
    code[0x10..0x16].copy_from_slice(&[0xe8, 0xeb, 0x0f, 0, 0, 0xc3]);
    code[0x20..0x2c].copy_from_slice(&[
        0x48, 0x8d, 0x4a, 1, 0x49, 0x89, 0x08, 0xe9, 0xe4, 0xff, 0xff, 0xff,
    ]);
    let hir = semantic_function(&code);
    let mut hints = ura_core::decomp::SignatureHints::default();
    hints.insert(signature(0x2000, &[("arg", "rcx", 64)]));
    let output = source::build(&hir, "caller", &hints, None, &()).unwrap();
    let arguments = output
        .ast
        .body
        .iter()
        .find_map(|s| {
            if let StatementKind::Call { arguments, .. } = &s.kind {
                Some(arguments)
            } else {
                None
            }
        })
        .unwrap();
    let mut referenced = Vec::new();
    arguments[0].variables(&mut referenced);
    for id in referenced {
        assert!(
            output.ast.variables[id].entry_register.is_some()
                || output
                    .ast
                    .body
                    .iter()
                    .any(|s| matches!(s.kind,StatementKind::Assign {variable,..} if variable==id)),
            "undefined call argument {id}"
        );
    }
    assert!(output
        .lines
        .iter()
        .any(|l| l.addresses.contains(&Address(0x1027))));
}

#[test]
fn simultaneous_copy_oracle_exhausts_cycles_fanout_and_widths() {
    for width in [1, 8, 32, 64] {
        for assignment in 0..256 {
            let mut variables: Vec<_> = (0..4).map(|i| variable(i, width)).collect();
            let values: Vec<_> = (0..4)
                .map(|i| (0xfedc_ba98_7654_3210u64.rotate_left(i * 13)) & ir::mask(width))
                .collect();
            let source_ids: Vec<_> = (0..4)
                .map(|i| ((assignment >> (i * 2)) & 3) as usize)
                .collect();
            let copies = source::parallel_copies(
                &mut variables,
                (0..4)
                    .map(|i| (i, Expr::variable(source_ids[i], Type::Bits(width))))
                    .collect(),
            )
            .unwrap();
            let mut body = copies;
            body.push(statement(StatementKind::Return {
                result: None,
                destination: None,
            }));
            let mut state = State::default();
            state.registers = (0..4).map(|i| (format!("r{i}"), values[i])).collect();
            state.run(&function(variables, body), 1000).unwrap();
            for i in 0..4 {
                assert_eq!(
                    state.value(i),
                    Some(values[source_ids[i]]),
                    "width {width}, moves {source_ids:?}"
                );
            }
        }
    }
}

#[test]
fn copies_reject_unevaluated_expressions_duplicate_destinations_and_width_mismatch() {
    let mut variables = vec![variable(0, 64), variable(1, 64)];
    assert!(source::parallel_copies(&mut variables, vec![(0, constant(32, 1))]).is_err());
    assert!(source::parallel_copies(
        &mut variables,
        vec![(0, constant(64, 1)), (0, constant(64, 2))]
    )
    .is_err());
    let add = Expr {
        storage: Type::Bits(64),
        source: None,
        kind: ExprKind::Scalar {
            operator: semantic::ScalarOp::Add,
            arguments: vec![Expr::variable(0, Type::Bits(64)), constant(64, 1)],
        },
    };
    assert!(source::parallel_copies(&mut variables, vec![(1, add)]).is_err());
}

#[test]
fn precedence_and_fixed_width_operations_are_ast_driven() {
    let inner = Expr {
        storage: Type::Bits(8),
        source: None,
        kind: ExprKind::Scalar {
            operator: semantic::ScalarOp::Subtract,
            arguments: vec![constant(8, 2), constant(8, 1)],
        },
    };
    let value = Expr {
        storage: Type::Bits(8),
        source: None,
        kind: ExprKind::Scalar {
            operator: semantic::ScalarOp::Subtract,
            arguments: vec![constant(8, 3), inner],
        },
    };
    let f = function(
        Vec::new(),
        vec![statement(StatementKind::Return {
            result: Some(value),
            destination: None,
        })],
    );
    let mut state = State::default();
    assert_eq!(
        state.run(&f, 100).unwrap(),
        Exit::Return {
            result: Some(2),
            destination: None
        }
    );
    let output = source::render(f, &()).unwrap();
    assert!(output.text().contains("return ((uint8_t)"));
    assert_eq!(
        output.text(),
        source::render(output.ast.clone(), &()).unwrap().text()
    );
}

#[test]
fn memory_reads_remain_ordered_and_are_never_inlined_across_writes() {
    // mov rax,[rcx]; mov [rcx],rdx; add rax,rdx; ret
    let output = reconstruct(&[0x48, 0x8b, 0x01, 0x48, 0x89, 0x11, 0x48, 0x01, 0xd0, 0xc3]);
    let text = output.text();
    assert_eq!(text.matches("ura_load_u64").count(), 2); // first load and RET destination
    assert!(text.find("ura_load_u64").unwrap() < text.find("ura_store_u64").unwrap());
    let mut state = State::default();
    state.registers = BTreeMap::from([
        ("rax".into(), 0),
        ("rcx".into(), 0x9000),
        ("rdx".into(), 7),
        ("rsp".into(), 0x8000),
    ]);
    for i in 0..8 {
        state.memory.insert(0x9000 + i, if i == 0 { 5 } else { 0 });
        state.memory.insert(0x8000 + i, 0);
    }
    assert_eq!(
        state.run(&output.ast, 1000).unwrap(),
        Exit::Return {
            result: Some(12),
            destination: Some(0)
        }
    );
    assert_eq!(state.memory[&0x9000], 7);
}

#[test]
fn phi_destruction_and_self_loop_have_no_phi_text_and_exact_provenance() {
    let code = [0x31, 0xc0, 0x83, 0xc0, 1, 0x83, 0xf8, 5, 0x7c, 0xf8, 0xc3];
    let output = reconstruct(&code);
    assert!(output.ast.phi_copies > 0);
    assert!(output.text().contains("while (true)"));
    assert!(!output.text().contains("phi("));
    let instructions: [u64; 5] = [0x1000, 0x1002, 0x1005, 0x1008, 0x100a];
    for line in &output.lines {
        assert!(
            line.addresses.iter().all(|a| instructions.contains(&a.0)),
            "{line:?}"
        );
    }
    let output2 = reconstruct(&code);
    assert_eq!(
        serde_json::to_string(&output).unwrap(),
        serde_json::to_string(&output2).unwrap()
    );
}

#[test]
fn unsupported_effects_remain_visible_and_stop_concrete_execution() {
    let output = reconstruct(&[0x0f, 0x0b]); // UD2
    assert!(output.unresolved > 0);
    assert_eq!(output.status, "partial");
    assert!(output.text().contains("ura_unknown_") || output.text().contains("ura_unresolved"));
    assert!(State::default().run(&output.ast, 100).is_err());
}
