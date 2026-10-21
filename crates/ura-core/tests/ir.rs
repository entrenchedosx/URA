use ura_core::ir::{
    self, dataflow, evaluate::Machine, ssa, Address, Operand, Operation, Type, VariableKind,
};
use ura_core::{analyze_image, AnalysisOptions, CodeImage, CodeRegion};

fn lift(bytes: &[u8], bits: u8) -> ir::Function {
    let image = CodeImage::new(vec![CodeRegion {
        start: 0x1000,
        bytes,
    }]);
    let analysis = analyze_image(
        &image,
        bits,
        Some(0x1000),
        &[],
        &AnalysisOptions::default(),
        &(),
    );
    ir::lift_image(&image, bits, &analysis, 0x1000, &()).unwrap()
}
fn machine() -> Machine {
    let mut m = Machine::default();
    for r in [
        "rax", "rbx", "rcx", "rdx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14", "r15", "eax", "ebx", "ecx", "edx", "esp", "ebp", "esi", "edi", "cf", "pf",
        "af", "zf", "sf", "of", "fs_base", "gs_base", "ds_base", "ss_base", "es_base", "cs_base",
    ] {
        m.values.insert(r.into(), 0);
    }
    m.values.insert("rsp".into(), 0x8000);
    m.values.insert("esp".into(), 0x8000);
    for i in 0..16 {
        m.memory.insert(0x8000 + i, 0);
    }
    m.memory.insert(0x8000, 0x42);
    m
}

#[test]
fn all_sixteen_conditions_match_boolean_truth_tables() {
    for bits in 0u8..32 {
        let (cf, pf, zf, sf, of) = (
            bits & 1 != 0,
            bits & 2 != 0,
            bits & 4 != 0,
            bits & 8 != 0,
            bits & 16 != 0,
        );
        let expected = [
            of,
            !of,
            cf,
            !cf,
            zf,
            !zf,
            cf || zf,
            !cf && !zf,
            sf,
            !sf,
            pf,
            !pf,
            sf != of,
            sf == of,
            zf || (sf != of),
            !zf && (sf == of),
        ];
        for (code, taken) in expected.into_iter().enumerate() {
            let f = lift(
                &[
                    0x70 + code as u8,
                    6,
                    0xb8,
                    0,
                    0,
                    0,
                    0,
                    0xc3,
                    0xb8,
                    1,
                    0,
                    0,
                    0,
                    0xc3,
                ],
                64,
            );
            let mut m = machine();
            for (flag, value) in [("cf", cf), ("pf", pf), ("zf", zf), ("sf", sf), ("of", of)] {
                m.values.insert(flag.into(), u64::from(value));
            }
            m.run(&f, 4).unwrap();
            assert_eq!(
                m.values["rax"],
                u64::from(taken),
                "condition {code} flags {bits}"
            );
        }
    }
}
#[test]
fn rex_byte_registers_and_extended_dword_aliases_are_distinct() {
    let f = lift(
        &[
            0x40, 0xb6, 0x12, 0xb6, 0x34, 0x41, 0xb1, 0x56, 0x41, 0xb9, 0x78, 0x56, 0x34, 0x12,
            0xc3,
        ],
        64,
    );
    let mut m = machine();
    m.values.insert("rsi".into(), 0x1122334455667788);
    m.values.insert("rdx".into(), 0x8877665544332211);
    m.values.insert("r9".into(), u64::MAX);
    m.run(&f, 4).unwrap();
    assert_eq!(m.values["rsi"], 0x1122334455667712);
    assert_eq!(m.values["rdx"], 0x8877665544333411);
    assert_eq!(m.values["r9"], 0x12345678);
}
#[test]
fn segment_memory_and_32_bit_stack_use_explicit_linear_addresses() {
    let f = lift(&[0x64, 0x48, 0x8b, 0x03, 0xc3], 64);
    let mut m = machine();
    m.values.insert("rbx".into(), 0x40);
    m.values.insert("fs_base".into(), 0x9000);
    for i in 0..8 {
        m.memory.insert(0x9040 + i, 0xaa);
    }
    m.run(&f, 4).unwrap();
    assert_eq!(m.values["rax"], 0xaaaaaaaaaaaaaaaa);
    let f = lift(&[0x50, 0x59, 0xc2, 0x10, 0], 32);
    let mut m = machine();
    m.values.insert("eax".into(), 0x12345678);
    m.values.insert("ss_base".into(), 0x10000);
    for i in 0..4 {
        m.memory.insert(0x18000 + i, 0);
    }
    m.run(&f, 4).unwrap();
    assert_eq!(m.values["ecx"], 0x12345678);
    assert_eq!(m.values["esp"], 0x8014);
}
#[test]
fn unsupported_far_jump_and_return_size_do_not_fabricate_targets() {
    let f = lift(&[0xea, 0, 0, 0, 0, 0, 0], 32);
    assert_eq!(f.blocks[0].terminator.kind, ir::FlowKind::Unresolved);
    assert!(!f.diagnostics.is_empty());
    let f = lift(&[0x66, 0xc3], 64);
    assert!(!f.diagnostics.is_empty());
    assert!(f.blocks[0].terminator.value.is_none());
}
#[test]
fn ssa_rejects_forged_dominance_inputs_outputs_and_sources() {
    let f = lift(
        &[
            0x85, 0xc0, 0x74, 7, 0xb8, 1, 0, 0, 0, 0xeb, 5, 0xb8, 2, 0, 0, 0, 0xc3,
        ],
        64,
    );
    let s = ssa::construct(&f).unwrap();
    let mut bad = s.clone();
    bad.dominators.preorder.insert(f.entry, usize::MAX);
    assert!(ssa::verify_ssa(&bad).is_err());
    let mut bad = s.clone();
    bad.blocks[0].statements[0].output.as_mut().unwrap().version = 0;
    assert!(ssa::verify_ssa(&bad).is_err());
    let mut bad = s.clone();
    bad.blocks[0].statements[0].source = Address(0);
    assert!(ssa::verify_ssa(&bad).is_err());
    let mut bad = s.clone();
    let phi = bad
        .blocks
        .iter_mut()
        .flat_map(|b| b.phis.iter_mut())
        .find(|p| s.variables[p.output.variable].name == "rax")
        .unwrap();
    let other = *phi.incoming.values().last().unwrap();
    let first = *phi.incoming.keys().next().unwrap();
    phi.incoming.insert(first, other);
    assert!(ssa::verify_ssa(&bad).is_err());
}
#[test]
fn entry_loop_phi_merges_unknown_initial_state_and_omits_unreachable_blocks() {
    let mut f = lift(&[0x83, 0xc0, 1, 0x75, 0xfb, 0xc3], 64);
    let mut unreachable = f.blocks.last().unwrap().clone();
    unreachable.address = Address(0x5000);
    unreachable.end = Address(0x5001);
    unreachable.statements.clear();
    unreachable.terminator.source = Address(0x5000);
    unreachable.terminator.value = Some(Operand::Constant(ir::Constant {
        ty: Type::Address(64),
        value: Address(0),
    }));
    f.blocks.push(unreachable);
    let s = ssa::construct(&f).unwrap();
    assert_eq!(s.omitted_unreachable, vec![Address(0x5000)]);
    assert!(s.blocks[0].phis.iter().all(|p| p
        .initial
        .is_some_and(|v| v.version == 0 && v.variable == p.output.variable)));
    assert!(!s.blocks[0].phis.is_empty());
    let mut bad = s.clone();
    bad.blocks[0].phis[0].initial.as_mut().unwrap().version = 1;
    assert!(ssa::verify_ssa(&bad).is_err());
}
#[test]
fn memory_loads_are_not_folded_across_aliases_and_exit_uses_are_counted() {
    let f = lift(
        &[0x48, 0x89, 0x03, 0x48, 0x8b, 0x0b, 0xb8, 1, 0, 0, 0, 0xc3],
        64,
    );
    let s = ssa::construct(&f).unwrap();
    let d = dataflow::analyze(&s).unwrap();
    for load in s
        .blocks
        .iter()
        .flat_map(|b| &b.statements)
        .filter(|s| s.op == Operation::Load)
    {
        let output = load.output.unwrap();
        assert!(!d.constants.iter().any(|(v, _)| *v == output));
        assert!(!d.dead_definitions.contains(&output));
    }
    let last_rax = d
        .definitions
        .iter()
        .rev()
        .find(|def| s.variables[def.value.variable].name == "rax")
        .unwrap();
    assert!(last_rax.uses > 0);
}
#[test]
fn ir_passes_honor_cancellation_and_source_and_size_budgets() {
    struct Cancel;
    impl ura_core::AnalysisControl for Cancel {
        fn is_cancelled(&self) -> bool {
            true
        }
        fn report(&self, _: ura_core::AnalysisProgress) {}
    }
    let f = lift(&[0xb8, 1, 0, 0, 0, 0xc3], 64);
    assert!(ssa::construct_with_control(&f, &Cancel)
        .unwrap_err()
        .contains("cancelled"));
    let s = ssa::construct(&f).unwrap();
    assert!(dataflow::analyze_with_control(&s, &Cancel)
        .unwrap_err()
        .contains("cancelled"));
    let mut bad = f.clone();
    bad.blocks[0].end = bad.blocks[0].address;
    assert!(ir::verify(&bad).is_err());
    let mut code = vec![0x90; ir::MAX_IR_INSTRUCTIONS + 1];
    code.push(0xc3);
    let image = CodeImage::new(vec![CodeRegion {
        start: 0x1000,
        bytes: &code,
    }]);
    let a = analyze_image(&image, 64, Some(0x1000), &[], &Default::default(), &());
    assert!(ir::lift_image(&image, 64, &a, 0x1000, &())
        .unwrap_err()
        .contains("budget"));
}

#[test]
fn partial_writes_preserve_other_bits_and_eax_clears_high_half() {
    let f = lift(&[0xb0, 0x12, 0xb4, 0x34, 0x66, 0xb8, 0x78, 0x56, 0xc3], 64);
    let mut m = machine();
    m.values.insert("rax".into(), 0x1122334455667788);
    m.run(&f, 10).unwrap();
    assert_eq!(m.values["rax"], 0x1122334455665678);
    let f = lift(&[0xb8, 0x78, 0x56, 0x34, 0x12, 0xc3], 64);
    m.values.insert("rax".into(), u64::MAX);
    m.values.insert("rsp".into(), 0x8000);
    m.run(&f, 10).unwrap();
    assert_eq!(m.values["rax"], 0x12345678);
}
#[test]
fn sign_extension_and_immediate_extension_are_exact() {
    for (bytes, expected) in [
        (
            vec![0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0xc3],
            u64::MAX,
        ),
        (vec![0x48, 0x0f, 0xbe, 0xc3, 0xc3], 0xffffffffffffff80),
        (vec![0x0f, 0xb6, 0xc3, 0xc3], 0x80),
    ] {
        let f = lift(&bytes, 64);
        let mut m = machine();
        m.values.insert("rbx".into(), 0x80);
        m.run(&f, 10).unwrap();
        assert_eq!(m.values["rax"], expected);
    }
}
#[test]
fn add_and_sub_flags_match_integer_oracles_at_byte_boundaries() {
    for (opcode, subtract) in [(0x00, false), (0x28, true)] {
        let f = lift(&[opcode, 0xd8, 0xc3], 64); // add/sub al,bl
        for a in [0u64, 1, 7, 15, 16, 63, 127, 128, 129, 240, 254, 255] {
            for b in [0u64, 1, 15, 16, 127, 128, 129, 255] {
                let mut m = machine();
                m.values.insert("rax".into(), a);
                m.values.insert("rbx".into(), b);
                m.run(&f, 10).unwrap();
                let result = if subtract { a.wrapping_sub(b) } else { a + b } & 255;
                let signed = if subtract {
                    (a as u8 as i8 as i16) - (b as u8 as i8 as i16)
                } else {
                    (a as u8 as i8 as i16) + (b as u8 as i8 as i16)
                };
                assert_eq!(m.values["rax"] & 255, result);
                assert_eq!(
                    m.values["cf"],
                    u64::from(if subtract { a < b } else { a + b > 255 })
                );
                assert_eq!(m.values["of"], u64::from(!(-128..=127).contains(&signed)));
                assert_eq!(m.values["zf"], u64::from(result == 0));
                assert_eq!(m.values["sf"], result >> 7);
                assert_eq!(
                    m.values["pf"],
                    u64::from((result as u8).count_ones() % 2 == 0)
                );
                assert_eq!(
                    m.values["af"],
                    u64::from(if subtract {
                        a & 15 < b & 15
                    } else {
                        (a & 15) + (b & 15) > 15
                    })
                );
            }
        }
    }
}
#[test]
fn arithmetic_wraps_at_each_operand_width() {
    for (bytes, width) in [
        (vec![0x00, 0xd8, 0xc3], 8),
        (vec![0x66, 0x01, 0xd8, 0xc3], 16),
        (vec![0x01, 0xd8, 0xc3], 32),
        (vec![0x48, 0x01, 0xd8, 0xc3], 64),
    ] {
        let f = lift(&bytes, 64);
        let mut m = machine();
        m.values.insert("rax".into(), ir::mask(width));
        m.values.insert("rbx".into(), 1);
        m.run(&f, 10).unwrap();
        assert_eq!(m.values["rax"] & ir::mask(width), 0);
        assert_eq!(m.values["cf"], 1);
        assert_eq!(m.values["zf"], 1);
    }
}
#[test]
fn logical_flags_and_undefined_af_remain_explicit() {
    for opcode in [0x20, 0x08, 0x30, 0x84] {
        // and/or/xor/test al,bl
        let f = lift(&[opcode, 0xd8, 0xc3], 64);
        let mut m = machine();
        m.values.insert("rax".into(), 0x80);
        m.values.insert("rbx".into(), 0x80);
        m.run(&f, 10).unwrap();
        assert_eq!(m.values["cf"], 0);
        assert_eq!(m.values["of"], 0);
        assert!(!m.values.contains_key("af"));
    }
}
#[test]
fn lea_ignores_segment_base_and_wraps_address_override() {
    let f = lift(&[0x64, 0x48, 0x8d, 0x43, 0xf8, 0xc3], 64);
    let mut m = machine();
    m.values.insert("rbx".into(), 0x100);
    m.values.insert("fs_base".into(), 0x9000);
    m.run(&f, 10).unwrap();
    assert_eq!(m.values["rax"], 0xf8);
    let f = lift(&[0x67, 0x48, 0x8d, 0x43, 0x08, 0xc3], 64);
    let mut m = machine();
    m.values.insert("rbx".into(), 0xfffffffc);
    m.run(&f, 10).unwrap();
    assert_eq!(m.values["rax"], 4);
    let f = lift(&[0x8d, 0x43, 0xf8, 0xc3], 32);
    let mut m = machine();
    m.values.insert("ebx".into(), 0x100);
    m.values.insert("ds_base".into(), 0x9000);
    m.run(&f, 10).unwrap();
    assert_eq!(m.values["eax"], 0xf8);
}
#[test]
fn memory_load_store_and_rip_provenance_are_explicit() {
    let f = lift(&[0x48, 0x89, 0x03, 0x48, 0x8b, 0x0b, 0xc3], 64);
    let mut m = machine();
    m.values.insert("rax".into(), 0x123456789abcdef0);
    m.values.insert("rbx".into(), 0x7000);
    m.run(&f, 10).unwrap();
    assert_eq!(m.values["rcx"], 0x123456789abcdef0);
    assert_eq!(m.memory[&0x7000], 0xf0);
    let f = lift(&[0x48, 0x8b, 0x05, 0x10, 0, 0, 0, 0xc3], 64);
    let mut m = machine();
    for n in 0..8 {
        m.memory.insert(0x1017 + n, n as u8);
    }
    m.run(&f, 10).unwrap();
    assert_eq!(m.values["rax"], 0x0706050403020100);
    assert!(f.blocks[0]
        .statements
        .iter()
        .filter(|s| s.op == Operation::Load)
        .any(|s| s.source == Address(0x1000)));
}
#[test]
fn push_rsp_snapshots_old_pointer_and_pop_rsp_writes_last() {
    let f = lift(&[0x54, 0x58, 0xc3], 64);
    let mut m = machine();
    m.run(&f, 10).unwrap();
    assert_eq!(m.values["rax"], 0x8000);
    assert_eq!(m.values["rsp"], 0x8008);
    let f = lift(&[0x5c, 0xc3], 64);
    let mut m = machine();
    for i in 0..8 {
        m.memory
            .insert(0x8000 + i, ((0x7000u64 >> (i * 8)) & 255) as u8);
        m.memory.insert(0x7000 + i, 0);
    }
    m.run(&f, 10).unwrap();
    assert_eq!(m.values["rsp"], 0x7008);
}
#[test]
fn cmp_and_jcc_execute_correct_paths() {
    // cmp eax,1; jne B; mov eax,5; ret; B: mov eax,9; ret
    let f = lift(
        &[
            0x83, 0xf8, 1, 0x75, 6, 0xb8, 5, 0, 0, 0, 0xc3, 0xb8, 9, 0, 0, 0, 0xc3,
        ],
        64,
    );
    for (input, expected) in [(1, 5), (2, 9)] {
        let mut m = machine();
        m.values.insert("rax".into(), input);
        m.run(&f, 10).unwrap();
        assert_eq!(m.values["rax"], expected);
    }
}
#[test]
fn unsupported_instruction_and_call_invalidate_constants() {
    let f = lift(&[0xb8, 7, 0, 0, 0, 0x0f, 0xa2, 0xc3], 64); // CPUID
    assert!(!f.diagnostics.is_empty());
    assert!(f.blocks[0]
        .statements
        .iter()
        .any(|s| matches!(s.op, Operation::Barrier { .. })));
    let s = ssa::construct(&f).unwrap();
    let d = dataflow::analyze(&s).unwrap();
    let last = s.blocks[0]
        .statements
        .iter()
        .rev()
        .find(|s| s.output.is_some_and(|v| v.variable == 0))
        .unwrap()
        .output
        .unwrap();
    assert!(!d.constants.iter().any(|(v, _)| *v == last));
    let f = lift(&[0xb8, 7, 0, 0, 0, 0xe8, 1, 0, 0, 0, 0xc3, 0xc3], 64);
    assert!(f.blocks[0]
        .statements
        .iter()
        .any(|s| s.op == Operation::Call));
}
#[test]
fn verifier_rejects_bad_width_edges_and_temporary_uses() {
    let f = lift(&[0xeb, 0, 0xc3], 64);
    let mut bad = ssa::construct(&f).unwrap();
    let wrong = ir::Constant {
        ty: Type::Address(64),
        value: Address(0x9999),
    };
    bad.blocks[0].terminator.value = Some(ssa::Use::Constant(wrong));
    bad.blocks[0].terminator.flow.value = Some(Operand::Constant(wrong));
    assert!(ssa::verify_ssa(&bad).is_err());
    let mut bad = f;
    bad.blocks[0].terminator.value = Some(Operand::Constant(wrong));
    assert!(ir::verify(&bad).is_err());
    let mut f = lift(&[0xb8, 7, 0, 0, 0, 0xc3], 64);
    f.blocks[0].terminator.successors.push(Address(0x9999));
    assert!(ir::verify(&f).is_err());
    let mut f = lift(&[0xb8, 7, 0, 0, 0, 0xc3], 64);
    f.variables[0].ty = Type::Bits(0);
    assert!(ir::verify(&f).is_err());
    let mut f = lift(&[0xb8, 7, 0, 0, 0, 0xc3], 64);
    let id = f
        .variables
        .iter()
        .position(|v| v.kind == VariableKind::Temporary)
        .unwrap();
    f.blocks[0].statements[0].args = vec![Operand::Variable(id)];
    assert!(ir::verify(&f).is_err());
}
#[test]
fn diamond_places_phi_and_dominance_frontier() {
    // test ecx,ecx; jz B; eax=1; jmp J; B:eax=2; J:ret
    let f = lift(
        &[
            0x85, 0xc9, 0x74, 7, 0xb8, 1, 0, 0, 0, 0xeb, 5, 0xb8, 2, 0, 0, 0, 0xc3,
        ],
        64,
    );
    let dom = ssa::dominators(&f).unwrap();
    assert_eq!(dom.immediate[&Address(0x1010)], Address(0x1000));
    assert!(dom.frontiers[&Address(0x1004)].contains(&Address(0x1010)));
    let s = ssa::construct(&f).unwrap();
    let join = s
        .blocks
        .iter()
        .find(|b| b.address == Address(0x1010))
        .unwrap();
    assert!(join
        .phis
        .iter()
        .any(|p| p.output.variable == 0 && p.incoming.len() == 2));
    ssa::verify_ssa(&s).unwrap();
    let d = dataflow::analyze(&s).unwrap();
    let phi = join.phis.iter().find(|p| p.output.variable == 0).unwrap();
    assert!(!d.constants.iter().any(|(v, _)| *v == phi.output));
}
#[test]
fn loops_have_valid_phi_inputs_and_unknown_fixpoint() {
    let f = lift(
        &[
            0xb8, 0, 0, 0, 0, 0x83, 0xc0, 1, 0x83, 0xf8, 3, 0x75, 0xf8, 0xc3,
        ],
        64,
    );
    let s = ssa::construct(&f).unwrap();
    assert!(s.blocks.iter().any(|b| !b.phis.is_empty()));
    ssa::verify_ssa(&s).unwrap();
    let _ = dataflow::analyze(&s).unwrap();
    let mut m = machine();
    m.run(&f, 20).unwrap();
    assert_eq!(m.values["rax"], 3);
}
#[test]
fn propagation_proves_supported_branch_and_keeps_side_effects_live() {
    let f = lift(&[0x31, 0xc0, 0x85, 0xc0, 0x75, 1, 0xc3, 0xc3], 64);
    let s = ssa::construct(&f).unwrap();
    let d = dataflow::analyze(&s).unwrap();
    assert_eq!(d.proven_branches.get(&Address(0x1000)), Some(&false));
    for b in &s.blocks {
        for statement in &b.statements {
            if statement.op.observable() {
                if let Some(v) = statement.output {
                    assert!(!d.dead_definitions.contains(&v));
                }
            }
        }
    }
}
#[test]
fn pe_and_elf_lift_and_verify_with_source_cfg_parity() {
    for name in ["ura64.exe", "ura64.elf"] {
        let binary = ura_core::analyze_path(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures")
                .join(name),
        )
        .unwrap();
        let a = ura_core::analyze_functions(&binary, &Default::default(), &());
        for function in &a.functions {
            let f = ir::lift_function(&binary, &a, function.address, &()).unwrap();
            assert_eq!(
                f.blocks.iter().map(|b| b.address.0).collect::<Vec<_>>(),
                function.blocks
            );
            ssa::verify_ssa(&ssa::construct(&f).unwrap()).unwrap();
        }
    }
}
