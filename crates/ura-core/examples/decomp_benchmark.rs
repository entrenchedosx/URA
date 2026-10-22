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
        let mut import_ms = 0.0;
        let mut program_ms = 0.0;
        let mut pipeline_ms = 0.0;
        let mut program_result = None;
        let mut ast_bytes = 0;
        let mut semantic_ms = 0.0;
        let mut render_ms = 0.0;
        let mut serialization_ms = 0.0;
        let mut semantic_bytes = 0;
        let mut lines = 0;
        let mut unresolved = 0;
        let mut decompile_ms = 0.0;
        let mut source_render_ms = 0.0;
        let mut source_bytes = 0;
        let mut source_lines = 0;
        for _ in 0..repeats {
            let timer = Instant::now();
            let frame = stack::recover(&binary, &analysis, function.address, None).expect("stack");
            stack_ms += timer.elapsed().as_secs_f64() * 1000.0;
            let timer = Instant::now();
            let recovered =
                abi::recover(&binary, &analysis, &bundle, &frame, &context.hints).expect("ABI");
            abi_ms += timer.elapsed().as_secs_f64() * 1000.0;
            let timer = Instant::now();
            let inferred = black_box(types::infer_types(&bundle));
            types_ms += timer.elapsed().as_secs_f64() * 1000.0;
            let timer = Instant::now();
            let semantic =
                decomp::semantic::lower(&bundle.ssa, &inferred.values, &()).expect("semantic HIR");
            semantic_ms += timer.elapsed().as_secs_f64() * 1000.0;
            let timer = Instant::now();
            let source = decomp::source::build_with_facts(
                &semantic,
                &function.fallback_name(),
                &context.hints,
                Some(&frame),
                &Default::default(),
                &bundle.dataflow.constants,
                &(),
            )
            .expect("C-like reconstruction");
            decompile_ms += timer.elapsed().as_secs_f64() * 1000.0;
            source_bytes = serde_json::to_vec(&source.ast)
                .expect("C-like AST JSON")
                .len();
            source_lines = source.lines.len();
            let timer = Instant::now();
            black_box(decomp::source::render(source.ast, &()).expect("C-like formatting"));
            source_render_ms += timer.elapsed().as_secs_f64() * 1000.0;
            let timer = Instant::now();
            let (high, ast) = hir::build_with_ast(
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
            let timer = Instant::now();
            black_box(hir::render_ast(&ast).expect("render HIR"));
            render_ms += timer.elapsed().as_secs_f64() * 1000.0;
            let timer = Instant::now();
            semantic_bytes = serde_json::to_vec(&semantic).expect("semantic JSON").len();
            serialization_ms += timer.elapsed().as_secs_f64() * 1000.0;
            let mut hints = context.hints.clone();
            let timer = Instant::now();
            black_box(decomp::imports::hydrate(&binary, &mut hints));
            import_ms += timer.elapsed().as_secs_f64() * 1000.0;
            let timer = Instant::now();
            program_result = Some(
                decomp::program::enrich(&binary, &analysis, &bundle, &mut hints, &())
                    .expect("program types"),
            );
            program_ms += timer.elapsed().as_secs_f64() * 1000.0;
            let timer = Instant::now();
            let pipeline =
                decomp::analyze_function(&binary, &analysis, function.address, &context, &())
                    .expect("full pipeline");
            pipeline_ms += timer.elapsed().as_secs_f64() * 1000.0;
            ast_bytes = serde_json::to_vec(&pipeline.ast).expect("typed AST").len();
            black_box(pipeline);
        }
        println!(
            "{}",
            serde_json::json!({"function":ura_core::format_address(function.address),"instructions":function.instruction_count,"repetitions":repeats,"cDecompileMs":decompile_ms/repeats as f64,"cRenderMs":source_render_ms/repeats as f64,"cAstBytes":source_bytes,"cLines":source_lines,"stackMs":stack_ms/repeats as f64,"abiMs":abi_ms/repeats as f64,"typesMs":types_ms/repeats as f64,"highLevelMs":hir_ms/repeats as f64,"importMs":import_ms/repeats as f64,"programMs":program_ms/repeats as f64,"pipelineMs":pipeline_ms/repeats as f64,"program":program_result.as_ref().map(|report|report.protocol_view(function.address)),"semanticMs":semantic_ms/repeats as f64,"renderMs":render_ms/repeats as f64,"semanticSerializationMs":serialization_ms/repeats as f64,"semanticBytes":semantic_bytes,"typedAstBytes":ast_bytes,"lines":lines,"unresolved":unresolved})
        );
    }
}
