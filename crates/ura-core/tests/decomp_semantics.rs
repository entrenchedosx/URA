//! The original raw-IR interpreter and the semantic-HIR executor have separate
//! arithmetic, memory and control implementations. Neither runs native code.
use ura_core::decomp::{
    execute::{self, Exit},
    semantic, types,
};
use ura_core::ir::{self, dataflow, evaluate::Machine, ssa, VariableKind};
use ura_core::{AnalysisOptions, CodeImage, CodeRegion};

fn lift(code: &[u8]) -> ir::Function {
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
    ir::lift_image(&image, 64, &analysis, 0x1000, &()).unwrap()
}
fn compare(code: &[u8], inputs: &[(String, u64)], limit: usize) {
    compare_raw(lift(code), code, inputs, limit);
}
fn compare_raw(
    raw: ir::Function,
    code: &[u8],
    inputs: &[(String, u64)],
    limit: usize,
) -> execute::State {
    let ssa = ssa::construct(&raw).unwrap();
    let (types, _) = types::infer_ssa_types(&ssa, &()).unwrap();
    let hir = semantic::lower(&ssa, &types, &()).unwrap();
    // Constant propagation is deliberately not used to execute either model.
    let _ = dataflow::analyze(&ssa).unwrap();
    let mut reference = Machine::default();
    for variable in &raw.variables {
        if variable.kind != VariableKind::Temporary && variable.ty.width().is_some() {
            reference.values.insert(variable.name.clone(), 0);
        }
    }
    for (name, value) in inputs {
        reference.values.insert(name.clone(), *value);
    }
    reference.values.insert("rsp".into(), 0x8000);
    for offset in 0..16 {
        reference.memory.insert(0x8000 + offset, 0);
    }
    reference.memory.insert(0x8000, 0x42);
    for offset in 0..16 {
        reference.memory.insert(0x9000 + offset, (offset * 7) as u8);
    }
    let mut actual = execute::State {
        registers: reference.values.clone(),
        memory: reference.memory.clone(),
        trace: Vec::new(),
    };
    let expected = reference.run(&raw, limit);
    let result = actual.run(&hir, limit);
    let complete = expected.is_ok() && result.is_ok();
    if !code.starts_with(&[0xff, 0xd0]) && code != [0xeb, 0xfe] {
        assert!(
            complete,
            "supported fixture did not execute: {expected:?} vs {result:?}; bytes={code:x?}"
        );
    }
    match (expected, result) {
        (Ok(expected), Ok(Exit::Return(value) | Exit::Indirect(value))) => {
            assert_eq!(value, expected)
        }
        (Ok(expected), Ok(Exit::External(value))) => assert_eq!(Some(value.0), expected),
        (Err(expected), Err(actual)) if expected.contains("budget") => {
            assert!(actual.contains("budget"), "{actual}")
        }
        (Err(expected), Err(actual)) if expected.contains("unknown") => {
            assert!(actual.contains("unknown"), "{actual}")
        }
        (expected, actual) => {
            panic!("different outcomes: {expected:?} vs {actual:?}; bytes={code:x?}")
        }
    }
    // Compare state only after successful termination; an unknown effect stops
    // before either interpreter has a concrete complete state.
    if complete {
        assert_eq!(
            actual.registers, reference.values,
            "registers for {code:x?} inputs={inputs:?}"
        );
        assert_eq!(actual.memory, reference.memory, "memory for {code:x?}");
        assert_eq!(actual.trace, reference.trace, "control path differs");
    }
    actual
}
fn input(rcx: u64, rdx: u64) -> Vec<(String, u64)> {
    vec![("rcx".into(), rcx), ("rdx".into(), rdx)]
}

#[test]
fn bounded_exhaustive_integer_and_partial_register_semantics() {
    let programs: &[&[u8]] = &[
        &[
            0x48, 0x89, 0xc8, 0x48, 0x01, 0xd0, 0x48, 0x83, 0xe8, 3, 0xc3,
        ],
        &[0x48, 0x89, 0xc8, 0xb0, 0xa5, 0x88, 0xd4, 0xc3], // AL/AH inserts preserve unrelated bits
        &[0x48, 0x0f, 0xbe, 0xc1, 0xc3],                   // signed byte extension
        &[0x48, 0x89, 0xc8, 0x48, 0x31, 0xd0, 0xc3],
        &[
            0x48, 0x39, 0xd1, 0x72, 6, 0xb8, 0, 0, 0, 0, 0xc3, 0xb8, 1, 0, 0, 0, 0xc3,
        ],
    ];
    for code in programs {
        for a in 0..16 {
            for b in 0..16 {
                compare(code, &input(a * 17, b * 0x111111111111111), 64);
            }
        }
    }
}

#[test]
fn diamonds_multiple_returns_and_loop_phis_agree() {
    let programs: &[&[u8]] = &[
        &[
            0x85, 0xc9, 0x75, 4, 0x89, 0xc8, 0xeb, 2, 0x89, 0xd0, 0x8b, 0xc0, 0xc3,
        ],
        &[
            0x85, 0xc9, 0x74, 6, 0xb8, 1, 0, 0, 0, 0xc3, 0xb8, 2, 0, 0, 0, 0xc3,
        ],
        &[
            0x31, 0xc0, 0x48, 0x83, 0xf9, 0, 0x74, 9, 0x48, 0x01, 0xc8, 0x48, 0x83, 0xe9, 1, 0xeb,
            0xf1, 0xc3,
        ],
    ];
    for code in programs {
        for a in 0..16 {
            for b in 0..8 {
                compare(code, &input(a, b), 512);
            }
        }
    }
}

#[test]
fn nested_loop_execution_and_phi_selection_agree() {
    let code = [
        0x31, 0xc0, 0x49, 0x89, 0xd0, 0x48, 0x85, 0xc9, 0x74, 0x18, 0x4c, 0x89, 0xc2, 0x48, 0x85,
        0xd2, 0x74, 0x0a, 0x48, 0x83, 0xc0, 1, 0x48, 0x83, 0xea, 1, 0xeb, 0xf1, 0x48, 0x83, 0xe9,
        1, 0xeb, 0xe3, 0xc3,
    ];
    for a in 0..8 {
        for b in 0..8 {
            compare(&code, &input(a, b), 512);
        }
    }
}

#[test]
fn irreducible_two_entry_cycle_retains_explicit_control_semantics() {
    let code = [
        0x48, 0x85, 0xc9, 0x74, 8, 0x48, 0x83, 0xea, 1, 0x74, 8, 0xeb, 0, 0x48, 0x83, 0xe9, 1,
        0x75, 0xf2, 0xc3,
    ];
    for a in 0..8 {
        for b in 1..8 {
            compare(&code, &input(a, b), 512);
        }
    }
}

#[test]
fn memory_and_address_casts_agree() {
    // mov rax,[rcx]; add rax,rdx; mov [rcx+8],rax; ret
    let code = [
        0x48, 0x8b, 0x01, 0x48, 0x01, 0xd0, 0x48, 0x89, 0x41, 8, 0xc3,
    ];
    for value in 0..64 {
        compare(&code, &input(0x9000, value), 64);
    }
}

#[test]
fn infinite_external_indirect_and_unknown_paths_are_explicit() {
    compare(&[0xeb, 0xfe], &[], 64);
    compare(&[0xe9, 0xfb, 0x0f, 0, 0], &[], 64);
    compare(&[0xff, 0xe0], &[("rax".into(), 0x1234)], 64);
    compare(&[0xff, 0xd0, 0xc3], &[("rax".into(), 0x1234)], 64);
}

#[test]
fn stable_ids_exact_operands_synthetic_provenance_and_ssa_types() {
    // RAX's first value is used as a load address; a later unrelated version
    // holds an integer. A legacy register summary must not merge these types.
    let raw = lift(&[0x48, 0x89, 0xc8, 0x48, 0x8b, 0x10, 0xb8, 7, 0, 0, 0, 0xc3]);
    let ssa = ssa::construct(&raw).unwrap();
    let (types, partial) = types::infer_ssa_types(&ssa, &()).unwrap();
    assert!(!partial);
    let rax = ssa.variables.iter().position(|v| v.name == "rax").unwrap();
    let entries: Vec<_> = types.iter().filter(|ty| ty.value.variable == rax).collect();
    assert!(entries
        .iter()
        .any(|ty| matches!(ty.ty, types::TypeRef::Pointer { .. })));
    assert!(entries
        .iter()
        .any(|ty| matches!(ty.ty, types::TypeRef::Int { .. })));
    let hir = semantic::lower(&ssa, &types, &()).unwrap();
    let again = semantic::lower(&ssa, &types, &()).unwrap();
    assert_eq!(
        serde_json::to_value(&hir).unwrap(),
        serde_json::to_value(again).unwrap()
    );
    assert_eq!(
        hir.nodes.len(),
        ssa.blocks
            .iter()
            .map(|b| b.statements.len() + b.phis.len())
            .sum::<usize>()
    );
    for node in &hir.nodes {
        let source = &hir.sources[node.source];
        assert_eq!(source.synthetic, source.instruction.is_none());
    }
    let mut malformed = hir;
    malformed.values[0].storage = ir::Type::Bits(0);
    assert!(execute::State::default().run(&malformed, 64).is_err());
}

#[test]
fn clang_pe_and_elf_o0_o2_match_reference_execution_and_known_c_results() {
    use std::path::Path;
    for (name, bytes) in [
        (
            "semantic-O0.exe",
            include_bytes!("../../../tests/fixtures/semantic-O0.exe").as_slice(),
        ),
        (
            "semantic-O2.exe",
            include_bytes!("../../../tests/fixtures/semantic-O2.exe").as_slice(),
        ),
        (
            "semantic-O0.elf",
            include_bytes!("../../../tests/fixtures/semantic-O0.elf").as_slice(),
        ),
        (
            "semantic-O2.elf",
            include_bytes!("../../../tests/fixtures/semantic-O2.elf").as_slice(),
        ),
    ] {
        let binary = ura_core::binary::analyze_bytes(Path::new(name), bytes.to_vec()).unwrap();
        let analysis = ura_core::analyze_functions(&binary, &AnalysisOptions::default(), &());
        let (a, b) = if name.ends_with(".exe") {
            ("rcx", "rdx")
        } else {
            ("rdi", "rsi")
        };
        for function_name in ["semantic_sum", "semantic_memory", "semantic_loop"] {
            let function = analysis
                .functions
                .iter()
                .find(|function| {
                    analysis.function_name(function.address).as_deref() == Some(function_name)
                })
                .unwrap_or_else(|| panic!("missing {function_name} in {name}"));
            for value in 0..8u64 {
                let first = if function_name == "semantic_memory" {
                    0x9000
                } else if function_name == "semantic_loop" {
                    value * 3
                } else {
                    value
                };
                let raw = ir::lift_function(&binary, &analysis, function.address, &()).unwrap();
                let actual =
                    compare_raw(raw, &[], &[(a.into(), first), (b.into(), value + 7)], 512);
                let expected = match function_name {
                    "semantic_sum" => value.wrapping_add(value + 7).wrapping_add(3),
                    "semantic_loop" => 3 * value * (value + 1) / 2,
                    _ => u64::from_le_bytes([0, 7, 14, 21, 28, 35, 42, 49]).wrapping_add(value + 7),
                };
                assert_eq!(
                    actual.registers["rax"], expected,
                    "{name} {function_name} input={value}"
                );
            }
        }
    }
}

#[test]
fn cancellation_is_observed_by_semantic_lowering_and_ssa_type_passes() {
    struct Cancel;
    impl ura_core::AnalysisControl for Cancel {
        fn is_cancelled(&self) -> bool {
            true
        }
        fn report(&self, _: ura_core::AnalysisProgress) {}
    }
    let ssa = ssa::construct(&lift(&[0x48, 0x89, 0xc8, 0xc3])).unwrap();
    assert!(semantic::lower(&ssa, &[], &Cancel)
        .unwrap_err()
        .contains("cancelled"));
    assert!(types::infer_ssa_types(&ssa, &Cancel)
        .unwrap_err()
        .contains("cancelled"));
}

#[test]
fn opaque_memory_does_not_reuse_stale_concrete_bytes() {
    let mut raw = lift(&[0x48, 0x8b, 0x01, 0xc3]);
    let memory = raw
        .variables
        .iter()
        .position(|variable| variable.kind == VariableKind::Memory)
        .unwrap();
    raw.blocks[0].statements.insert(
        0,
        ir::Statement {
            source: raw.entry,
            output: Some(memory),
            op: ir::Operation::Unknown {
                reason: "opaque memory mutation".into(),
            },
            args: vec![],
        },
    );
    let ssa = ssa::construct(&raw).unwrap();
    let hir = semantic::lower(&ssa, &[], &()).unwrap();
    let mut original = Machine::default();
    original.values.insert("rcx".into(), 0x9000);
    original
        .memory
        .extend((0..8).map(|offset| (0x9000 + offset, 7)));
    let mut actual = execute::State {
        registers: original.values.clone(),
        memory: original.memory.clone(),
        trace: vec![],
    };
    assert!(original
        .run(&raw, 64)
        .unwrap_err()
        .contains("unknown memory"));
    assert!(actual.run(&hir, 64).unwrap_err().contains("unknown memory"));
}
