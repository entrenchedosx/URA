//! Synthetic supplied-prototype benchmark, separate from unseeded samples.
//! Code bytes are analyzed only. No sample executable is run.
use std::{hint::black_box, path::Path, time::Instant};
use ura_core::decomp::{
    self, CallingConvention, DecompContext, Location, SignatureOverride, SignatureParameterInput,
    TypeRef,
};

fn main() {
    if cfg!(debug_assertions) {
        eprintln!("run with --release");
        std::process::exit(1);
    }
    let mut bytes = include_bytes!("../../../tests/fixtures/ura64.exe").to_vec();
    let original =
        ura_core::binary::analyze_bytes(Path::new("wrapper-benchmark.exe"), bytes.clone()).unwrap();
    let entry = original.analysis().entry_point.unwrap();
    let offset = original
        .analysis()
        .section_containing_address(entry)
        .unwrap()
        .file_offset_for_address(entry)
        .unwrap() as usize;
    bytes[offset..offset + 96].fill(0xcc);
    let wrapper = [
        0x48, 0x83, 0xec, 0x28, 0xe8, 7, 0, 0, 0, 0x48, 0x83, 0xc4, 0x28, 0xc3,
    ];
    bytes[offset..offset + 14].copy_from_slice(&wrapper);
    bytes[offset + 16..offset + 30].copy_from_slice(&wrapper);
    bytes[offset + 32] = 0xc3;
    let binary =
        ura_core::binary::analyze_bytes(Path::new("wrapper-benchmark.exe"), bytes).unwrap();
    let analysis = ura_core::analyze_functions(
        &binary,
        &ura_core::AnalysisOptions {
            seed_symbols: false,
            ..Default::default()
        },
        &(),
    );
    let bundle = ura_core::ir::inspect::analyze(&binary, &analysis, entry, &()).unwrap();
    let mut context = DecompContext::new(64);
    context.hints.insert(decomp::signature::describe_override(
        entry + 32,
        "supplied_leaf",
        &SignatureOverride {
            convention: CallingConvention::Win64,
            return_type: TypeRef::Void,
            parameters: vec![SignatureParameterInput {
                name: "data".into(),
                location: Location::Register { name: "rcx".into() },
                ty: TypeRef::pointer_to(TypeRef::uint(8), 64),
            }],
            variadic: Some(false),
        },
    ));
    let repetitions = 100;
    let start = Instant::now();
    let mut report = None;
    for _ in 0..repetitions {
        let mut hints = context.hints.clone();
        report = Some(black_box(
            decomp::program::enrich(&binary, &analysis, &bundle, &mut hints, &()).unwrap(),
        ));
    }
    let ms = start.elapsed().as_secs_f64() * 1000.0 / repetitions as f64;
    let report = report.unwrap();
    assert!(report.converged && !report.truncated);
    assert_eq!(report.updates, 2);
    let pipeline_start = Instant::now();
    for _ in 0..repetitions {
        let result = decomp::analyze_function(&binary, &analysis, entry, &context, &()).unwrap();
        assert!(matches!(
            result.signature.parameters[0].ty,
            TypeRef::Pointer { .. }
        ));
        black_box(result);
    }
    println!(
        "{}",
        serde_json::json!({"fixture":"two Win64 wrappers and a supplied pointer prototype at the leaf", "repetitions":repetitions,"programMs":ms,"pipelineMs":pipeline_start.elapsed().as_secs_f64()*1000.0/repetitions as f64,"functions":report.functions.len(),"edges":report.edges.len(),"updates":report.updates,"converged":report.converged,"partial":report.truncated})
    );
}
