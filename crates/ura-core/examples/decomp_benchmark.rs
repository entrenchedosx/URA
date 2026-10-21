//! Release timing of individual decompiler passes. Input images are never run.
use std::{hint::black_box, path::Path, time::Instant};
use ura_core::{
    decomp::{self, abi, hir, stack, types, DecompContext},
    ir::inspect,
    AnalysisOptions,
};

fn main() {
    if cfg!(debug_assertions) {
        eprintln!("run with --release");
        std::process::exit(1);
    }
    let args: Vec<_> = std::env::args().collect();
    let path = Path::new(args.get(1).expect("binary path"));
    let repeats = args
        .get(2)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(5)
        .clamp(1, 20);
    let binary = ura_core::analyze_path(path).expect("read image");
    let started = Instant::now();
    let analysis = ura_core::analyze_functions(&binary, &AnalysisOptions::default(), &());
    let graph_start = Instant::now();
    let graph = decomp::build_call_graph(&analysis);
    let graph_ms = graph_start.elapsed().as_secs_f64() * 1000.0;
    println!(
        "{}",
        serde_json::json!({"sample":path.file_name().unwrap().to_string_lossy(),"sha256":binary.view().sha256,"discoveryMs":(graph_start - started).as_secs_f64()*1000.0,"callGraphMs":graph_ms,"functions":analysis.functions.len(),"instructions":analysis.instructions.len(),"partial":analysis.report.truncated,"graphNodes":graph.nodes.len(),"graphSites":graph.edges.len()})
    );
    let context = DecompContext::new(binary.analysis().bitness as u16);
    let mut functions: Vec<_> = analysis.functions.iter().collect();
    functions.sort_by_key(|f| std::cmp::Reverse(f.instruction_count));
    for function in functions.into_iter().take(16) {
        let bundle = match inspect::analyze(&binary, &analysis, function.address, &()) {
            Ok(bundle) => bundle,
            Err(error) => {
                println!(
                    "{}",
                    serde_json::json!({"function":ura_core::format_address(function.address),"error":error})
                );
                continue;
            }
        };
        let mut stack_ms = 0.0;
        let mut abi_ms = 0.0;
        let mut types_ms = 0.0;
        let mut hir_ms = 0.0;
        let mut lines = 0;
        let mut unresolved = 0;
        for _ in 0..repeats {
            let timer = Instant::now();
            let frame = stack::recover(&binary, &analysis, function.address, None).expect("stack");
            stack_ms += timer.elapsed().as_secs_f64() * 1000.0;
            let timer = Instant::now();
            let recovered =
                abi::recover(&binary, &analysis, &bundle, &frame, &context.hints).expect("ABI");
            abi_ms += timer.elapsed().as_secs_f64() * 1000.0;
            let timer = Instant::now();
            black_box(types::infer_types(&bundle));
            types_ms += timer.elapsed().as_secs_f64() * 1000.0;
            let timer = Instant::now();
            let high = hir::build(
                &bundle.ssa,
                &bundle.dataflow,
                &recovered.signature,
                &context.hints,
                Some(&frame),
            );
            hir_ms += timer.elapsed().as_secs_f64() * 1000.0;
            lines = high.lines.len();
            unresolved = high.unresolved;
            black_box(high);
        }
        println!(
            "{}",
            serde_json::json!({"function":ura_core::format_address(function.address),"instructions":function.instruction_count,"repetitions":repeats,"stackMs":stack_ms/repeats as f64,"abiMs":abi_ms/repeats as f64,"typesMs":types_ms/repeats as f64,"highLevelMs":hir_ms/repeats as f64,"lines":lines,"unresolved":unresolved})
        );
    }
}
