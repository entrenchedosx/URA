use ura_core::{analyze_image, AnalysisOptions, CodeImage, CodeRegion};

fn absolute() -> Vec<u8> {
    let mut code = vec![0x90; 0x108];
    code[..25].copy_from_slice(&[
        0x83, 0xf9, 1, 0x77, 7, 0xff, 0x24, 0x8d, 0, 0x11, 0, 0, 0xc3, 0xb8, 1, 0, 0, 0, 0xc3,
        0xb8, 2, 0, 0, 0, 0xc3,
    ]);
    code[0x100..0x104].copy_from_slice(&0x100du32.to_le_bytes());
    code[0x104..].copy_from_slice(&0x1013u32.to_le_bytes());
    code
}
fn relative() -> Vec<u8> {
    let mut code = vec![0x90; 0x108];
    code[..36].copy_from_slice(&[
        0x83, 0xff, 1, 0x77, 0x12, 0x89, 0xf8, 0x48, 0x8d, 0x15, 0xf2, 0, 0, 0, 0x48, 0x63, 0x04,
        0x82, 0x48, 0x01, 0xd0, 0xff, 0xe0, 0xc3, 0xb8, 1, 0, 0, 0, 0xc3, 0xb8, 2, 0, 0, 0, 0xc3,
    ]);
    code[0x100..0x104].copy_from_slice(&(-0xe8i32).to_le_bytes());
    code[0x104..].copy_from_slice(&(-0xe2i32).to_le_bytes());
    code
}
fn analyze(bytes: &[u8], bits: u8, blocks: usize) -> ura_core::ProgramAnalysis {
    let image = CodeImage::new(vec![CodeRegion {
        start: 0x1000,
        bytes,
    }]);
    analyze_image(
        &image,
        bits,
        Some(0x1000),
        &[],
        &AnalysisOptions {
            max_blocks: blocks,
            ..Default::default()
        },
        &(),
    )
}
#[test]
fn guarded_absolute_switch_recovers_real_cfg_edges() {
    let code = absolute();
    let a = analyze(&code, 32, 100);
    let table = &a.jump_tables[&0x1005];
    assert!(!table.relative);
    assert_eq!(table.guard, 0x1003);
    assert_eq!(table.table, 0x1100);
    assert_eq!(table.targets, vec![0x100d, 0x1013]);
    assert_eq!(
        a.blocks[&0x1005]
            .successors
            .iter()
            .map(|e| e.target)
            .collect::<Vec<_>>(),
        vec![0x100d, 0x1013]
    );
    assert!(a.report.diagnostics.is_empty());
}
#[test]
fn guarded_signed_relative_switch_preserves_indirect_ir_and_source_blocks() {
    let code = relative();
    let a = analyze(&code, 64, 100);
    let table = &a.jump_tables[&0x1015];
    assert!(table.relative);
    assert_eq!(table.targets, vec![0x1018, 0x101e]);
    let image = CodeImage::new(vec![CodeRegion {
        start: 0x1000,
        bytes: &code,
    }]);
    let ir = ura_core::ir::lift_image(&image, 64, &a, 0x1000, &()).unwrap();
    let transfer = ir
        .blocks
        .iter()
        .find(|b| b.terminator.source.0 == 0x1015)
        .unwrap();
    assert_eq!(transfer.terminator.kind, ura_core::ir::FlowKind::Indirect);
    assert_eq!(transfer.terminator.successors.len(), 2);
    assert!(!transfer.terminator.state.is_empty());
    ura_core::ir::ssa::construct(&ir).unwrap();
    assert_eq!(ir.blocks.len(), a.functions[0].blocks.len());
}
#[test]
fn tables_reject_truncation_outside_targets_overlaps_and_wrong_guards() {
    let mut cases = Vec::new();
    let mut x = absolute();
    x[4] = 0x2b;
    x[0x2f] = 0x89;
    x[0x30] = 0xc3;
    x[0x100..0x104].copy_from_slice(&0x102fu32.to_le_bytes());
    cases.push(x);
    let mut x = absolute();
    x.truncate(0x104);
    cases.push(x);
    let mut x = absolute();
    x[0x104..].copy_from_slice(&0x9999u32.to_le_bytes());
    cases.push(x);
    let mut x = absolute();
    x[0x104..].copy_from_slice(&0x100eu32.to_le_bytes());
    cases.push(x);
    let mut x = absolute();
    x[3] = 0x7f;
    cases.push(x); // signed greater is not an unsigned range bound
    let mut x = absolute();
    x[2] = 255;
    cases.push(x); // sign-extended immediate -1, no useful bound
    for code in cases {
        let a = analyze(&code, 32, 100);
        assert!(a.jump_tables.is_empty());
        assert!(a.blocks[&0x1005].successors.is_empty());
        assert!(a
            .report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("jump table") || d.message.contains("indirect transfer")));
    }
}
#[test]
fn high_index_bits_require_an_explicit_zero_extending_copy() {
    let mut code = relative();
    code[5] = 0x90;
    code[6] = 0x90;
    let a = analyze(&code, 64, 100);
    assert!(a.jump_tables.is_empty());
}

#[test]
fn separate_function_entries_support_conservative_tail_and_thunk_candidates() {
    let mut code = vec![0x90; 17];
    code[..5].copy_from_slice(&[0xe9, 11, 0, 0, 0]);
    code[16] = 0xc3;
    let image = CodeImage::new(vec![CodeRegion {
        start: 0x1000,
        bytes: &code,
    }]);
    let seed = ura_core::AnalysisSeed {
        address: 0x1010,
        name: None,
        origin: ura_core::FunctionOrigin::UserDefined,
    };
    let a = analyze_image(&image, 64, Some(0x1000), &[seed], &Default::default(), &());
    let facts = a.flow_facts(a.function_by_start(0x1000).unwrap());
    assert_eq!(facts.tail_calls, vec![(0x1000, 0x1010)]);
    assert!(facts.thunk_candidate);
    assert_eq!(facts.thunk_target, Some(0x1010));
    let code = [0xff, 0xe0];
    let a = analyze(&code, 64, 10);
    let facts = a.flow_facts(&a.functions[0]);
    assert_eq!(facts.unresolved_indirect, vec![0x1000]);
    assert!(facts.thunk_candidate);
    assert_eq!(facts.thunk_target, None);
}
#[test]
fn block_budget_retains_owned_blocks_and_prunes_dangling_edges() {
    let a = analyze(&relative(), 64, 1);
    assert!(a.report.truncated);
    assert_eq!(a.functions.len(), 1);
    assert_eq!(a.blocks.len(), 1);
    for (address, b) in &a.blocks {
        assert!(a
            .functions
            .iter()
            .any(|f| f.address == b.function && f.blocks.contains(address)));
        assert!(b
            .successors
            .iter()
            .all(|e| a.blocks.contains_key(&e.target)));
    }
    assert!(a.function_containing(0x1018).is_none());
}
#[test]
fn clang_optimized_pe_switches_recover_six_targets_without_executing_samples() {
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    for name in ["switch-O1.exe", "switch-O2.exe", "switch-O2.elf"] {
        let b = ura_core::analyze_path(&fixtures.join(name)).unwrap();
        let a = ura_core::analyze_functions(&b, &Default::default(), &());
        assert_eq!(a.jump_tables.len(), 1, "{name}: {:?}", a.report.diagnostics);
        let table = a.jump_tables.values().next().unwrap();
        assert_eq!(table.targets.len(), 6);
        assert!(table.relative);
        let f = a.function_containing(table.source).unwrap();
        assert!(table.targets.iter().all(|t| f.blocks.contains(t)));
        let ir = ura_core::ir::lift_function(&b, &a, f.address, &()).unwrap();
        assert_eq!(ir.blocks.len(), f.blocks.len());
        ura_core::ir::ssa::construct(&ir).unwrap();
    }
    // The unoptimized stack-spilled dispatch is deliberately outside coverage.
    let b = ura_core::analyze_path(&fixtures.join("switch-O0.exe")).unwrap();
    let a = ura_core::analyze_functions(&b, &Default::default(), &());
    assert!(a.jump_tables.is_empty());
    assert!(a
        .report
        .diagnostics
        .iter()
        .any(|d| d.message.contains("indirect transfer unresolved")));
}
