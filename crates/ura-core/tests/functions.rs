use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use ura_core::analysis::{
    analyze_binary, analyze_image, seeds_for_binary, AnalysisControl, AnalysisOptions,
    AnalysisProgress, AnalysisStage, CodeImage, CodeRegion, EdgeKind, FunctionOrigin,
    InstructionFlow, XrefKind,
};
use ura_core::{analyze_path, AnalysisSeed};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn analyze_fixture(options: &AnalysisOptions) -> ura_core::analysis::ProgramAnalysis {
    let binary = analyze_path(&fixture("ura64.exe")).expect("fixture should parse");
    analyze_binary(&binary, options, &())
}

fn analyze_code(
    bytes: &[u8],
    base: u64,
    entry: u64,
    seeds: &[AnalysisSeed],
    options: &AnalysisOptions,
) -> ura_core::analysis::ProgramAnalysis {
    let image = CodeImage::new(vec![CodeRegion { start: base, bytes }]);
    analyze_image(&image, 64, Some(entry), seeds, options, &())
}

#[test]
fn discovers_entry_and_call_target_functions() {
    let analysis = analyze_fixture(&AnalysisOptions::default());
    assert!(!analysis.report.cancelled);
    assert!(!analysis.report.truncated);
    assert_eq!(analysis.report.function_count, 2);

    let entry = analysis
        .function_by_start(0x140001000)
        .expect("entry should be discovered");
    assert_eq!(entry.origin, FunctionOrigin::EntryPoint);
    assert!(entry.verified());
    assert_eq!(entry.end, 0x140001014);
    assert!(entry.blocks.contains(&0x140001000));

    let callee = analysis
        .function_by_start(0x140001020)
        .expect("direct call target should be discovered");
    assert_eq!(callee.origin, FunctionOrigin::CallTarget);
    assert!(!callee.verified());

    assert_eq!(entry.callees, vec![0x140001020]);
    assert_eq!(callee.callers, vec![0x140001000]);
    assert!(callee.reference_count >= 1);

    let xrefs: Vec<_> = analysis.xrefs_to(0x140001020).collect();
    assert!(xrefs
        .iter()
        .any(|xref| xref.from == 0x140001004 && xref.kind == XrefKind::Call));
    assert!(analysis
        .xrefs_from(0x140001004)
        .any(|xref| xref.to == 0x140001020));
}

#[test]
fn builds_basic_blocks_and_loop_edges() {
    let analysis = analyze_fixture(&AnalysisOptions::default());
    let function = analysis
        .function_by_start(0x140001020)
        .expect("function should exist");
    assert_eq!(function.blocks, vec![0x140001020, 0x140001026, 0x14000102E]);

    let entry_block = &analysis.blocks[&0x140001020];
    assert_eq!(
        entry_block
            .successors
            .iter()
            .map(|edge| (edge.target, edge.kind))
            .collect::<Vec<_>>(),
        vec![(0x140001026, EdgeKind::FallThrough)]
    );

    let loop_block = &analysis.blocks[&0x140001026];
    assert_eq!(loop_block.successors.len(), 2);
    assert!(loop_block
        .successors
        .iter()
        .any(|edge| edge.target == 0x140001026 && edge.kind == EdgeKind::Taken));
    assert!(loop_block
        .successors
        .iter()
        .any(|edge| { edge.target == 0x14000102E && edge.kind == EdgeKind::FallThrough }));

    let tail = &analysis.blocks[&0x14000102E];
    assert!(tail.successors.is_empty());
    assert_eq!(tail.instructions.len(), 2);

    assert_eq!(
        analysis.function_containing(0x140001027).map(|f| f.address),
        Some(0x140001020)
    );
    assert_eq!(
        analysis.block_containing(0x140001027).map(|b| b.address),
        Some(0x140001026)
    );
    assert!(analysis.function_containing(0x140001100).is_none());
}

#[test]
fn indexes_conditional_branch_xrefs() {
    let analysis = analyze_fixture(&AnalysisOptions::default());
    let xrefs: Vec<_> = analysis.xrefs_to(0x140001026).collect();
    assert!(xrefs.iter().any(|xref| {
        xref.from == 0x14000102C
            && xref.kind == XrefKind::ConditionalJump
            && xref.function == Some(0x140001020)
    }));
}

#[test]
fn reports_invalid_instructions_without_panicking() {
    let bytes = [0x06, 0x90, 0xC3];
    let seed = AnalysisSeed {
        address: 0x1000,
        name: None,
        origin: FunctionOrigin::EntryPoint,
    };
    let analysis = analyze_code(&bytes, 0x1000, 0x1000, &[seed], &AnalysisOptions::default());
    assert_eq!(analysis.report.function_count, 1);
    assert_eq!(analysis.report.instruction_count, 1);
    let instruction = analysis.instructions.get(&0x1000).unwrap();
    assert!(instruction.invalid);
    assert_eq!(instruction.flow, InstructionFlow::Exception);
    assert!(analysis
        .report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("invalid instruction")));
}

#[test]
fn detects_seed_overlap_inside_instruction() {
    let bytes = [0xE8, 0x00, 0x00, 0x00, 0x00, 0x90, 0xC3, 0x90];
    let seeds = [
        AnalysisSeed {
            address: 0x1000,
            name: None,
            origin: FunctionOrigin::EntryPoint,
        },
        AnalysisSeed {
            address: 0x1002,
            name: Some("overlap".to_string()),
            origin: FunctionOrigin::Symbol,
        },
    ];
    let analysis = analyze_code(&bytes, 0x1000, 0x1000, &seeds, &AnalysisOptions::default());
    assert!(analysis.function_by_start(0x1002).is_none());
    assert!(analysis
        .report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic
            .message
            .contains("inside the instruction at 0x1000")));
}

#[test]
fn cancellation_returns_a_partial_report() {
    struct CancelAfter {
        checks: AtomicUsize,
        after: usize,
        stages: Mutex<Vec<AnalysisStage>>,
    }
    impl AnalysisControl for CancelAfter {
        fn is_cancelled(&self) -> bool {
            self.checks.fetch_add(1, Ordering::SeqCst) >= self.after
        }

        fn report(&self, progress: AnalysisProgress) {
            self.stages.lock().unwrap().push(progress.stage);
        }
    }

    let binary = analyze_path(&fixture("ura64.exe")).unwrap();
    let control = CancelAfter {
        checks: AtomicUsize::new(0),
        after: 2,
        stages: Mutex::new(Vec::new()),
    };
    let analysis = analyze_binary(&binary, &AnalysisOptions::default(), &control);
    assert!(analysis.report.cancelled);
    assert!(analysis
        .report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("cancelled")));
    let stages = control.stages.lock().unwrap().clone();
    assert!(stages.contains(&AnalysisStage::Preparing));
    assert!(stages.contains(&AnalysisStage::Complete));
}

#[test]
fn respects_instruction_limits() {
    struct StopControl;
    impl AnalysisControl for StopControl {
        fn is_cancelled(&self) -> bool {
            false
        }
        fn report(&self, _progress: AnalysisProgress) {}
    }

    let mut bytes = vec![0x90u8; 512];
    bytes.push(0xC3);
    let options = AnalysisOptions {
        max_instructions: 64,
        ..AnalysisOptions::default()
    };
    let seed = AnalysisSeed {
        address: 0x2000,
        name: None,
        origin: FunctionOrigin::EntryPoint,
    };
    let image = CodeImage::new(vec![CodeRegion {
        start: 0x2000,
        bytes: &bytes,
    }]);
    let analysis = analyze_image(&image, 64, Some(0x2000), &[seed], &options, &StopControl);
    assert!(analysis.report.truncated);
    assert!(analysis.report.instruction_count >= 64);
    assert!(analysis
        .report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("configured limit")));
}

#[test]
fn no_entry_or_seeds_produces_an_empty_result() {
    let bytes = [0x90, 0xC3];
    let image = CodeImage::new(vec![CodeRegion {
        start: 0x3000,
        bytes: &bytes,
    }]);
    let analysis = analyze_image(&image, 64, None, &[], &AnalysisOptions::default(), &());
    assert_eq!(analysis.report.function_count, 0);
    assert_eq!(analysis.report.instruction_count, 0);
    assert!(analysis.functions.is_empty());
}

#[test]
fn seeds_include_entry_and_symbols() {
    let binary = analyze_path(&fixture("ura64.elf")).unwrap();
    let seeds = seeds_for_binary(&binary);
    assert!(seeds
        .iter()
        .any(|seed| seed.address == 0x401000 && seed.origin == FunctionOrigin::EntryPoint));
    let analysis = analyze_binary(&binary, &AnalysisOptions::default(), &());
    assert_eq!(analysis.report.function_count, 2);
    assert!(analysis.function_by_start(0x401000).is_some());
    assert!(analysis.function_by_start(0x401020).is_some());
}

#[test]
fn analyzes_a_real_system_binary_when_available() {
    let path = Path::new(r"C:\Windows\System32\where.exe");
    if !path.exists() {
        return;
    }
    let binary = match analyze_path(path) {
        Ok(binary) => binary,
        Err(_) => return,
    };
    let options = AnalysisOptions {
        max_instructions: 50_000,
        max_functions: 4_096,
        ..AnalysisOptions::default()
    };
    let analysis = analyze_binary(&binary, &options, &());
    assert!(!analysis.report.cancelled);
    assert!(analysis.report.function_count >= 1);
    for function in &analysis.functions {
        assert!(binary
            .analysis()
            .code_section_containing_address(function.address)
            .is_some());
    }
}
