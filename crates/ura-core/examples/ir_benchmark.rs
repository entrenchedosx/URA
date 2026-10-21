//! Release-only static-analysis timing harness. Samples are never executed.
use std::{hint::black_box, path::Path, time::Instant};
use ura_core::{
    ir::{self, dataflow, ssa},
    CodeImage, CodeRegion, ProgramAnalysis,
};

fn benchmark(
    name: &str,
    image: &CodeImage<'_>,
    bits: u8,
    analysis: &ProgramAnalysis,
    repetitions: usize,
) {
    let mut functions: Vec<_> = analysis.functions.iter().collect();
    functions.sort_by_key(|f| std::cmp::Reverse(f.instruction_count));
    for f in functions.into_iter().take(64) {
        let mut lift = Vec::new();
        let mut ssa_ms = Vec::new();
        let mut flow = Vec::new();
        let mut operations = 0;
        let mut unsupported = 0;
        let mut error = None;
        for _ in 0..repetitions {
            let start = Instant::now();
            let raw = match ir::lift_image(image, bits, analysis, f.address, &()) {
                Ok(f) => f,
                Err(e) => {
                    error = Some(e);
                    break;
                }
            };
            lift.push(start.elapsed().as_secs_f64() * 1000.0);
            operations = raw.blocks.iter().map(|b| b.statements.len()).sum();
            unsupported = raw.diagnostics.len();
            let start = Instant::now();
            let s = match ssa::construct(&raw) {
                Ok(s) => s,
                Err(e) => {
                    error = Some(e);
                    break;
                }
            };
            ssa_ms.push(start.elapsed().as_secs_f64() * 1000.0);
            let start = Instant::now();
            black_box(dataflow::analyze(&s).unwrap());
            flow.push(start.elapsed().as_secs_f64() * 1000.0);
        }
        let average = |v: &[f64]| {
            if v.is_empty() {
                0.0
            } else {
                v.iter().sum::<f64>() / v.len() as f64
            }
        };
        println!(
            "{}",
            serde_json::json!({"sample":name,"function":ura_core::format_address(f.address),"instructions":f.instruction_count,"blocks":f.blocks.len(),"operations":operations,"unsupported":unsupported,"repetitions":lift.len(),"liftMs":average(&lift),"ssaMs":average(&ssa_ms),"dataflowMs":average(&flow),"error":error})
        );
    }
}
fn main() {
    if cfg!(debug_assertions) {
        eprintln!("use --release for benchmarks");
        std::process::exit(1);
    }
    let args: Vec<_> = std::env::args().collect();
    let repetitions = args
        .get(2)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(5)
        .clamp(1, 20);
    if args.get(1).is_some_and(|s| s == "synthetic") {
        for count in [100, 1000, 4000] {
            let mut bytes = [0x83, 0xc0, 1].repeat(count);
            bytes.push(0xc3);
            let image = CodeImage::new(vec![CodeRegion {
                start: 0x1000,
                bytes: &bytes,
            }]);
            let started = Instant::now();
            let a =
                ura_core::analyze_image(&image, 64, Some(0x1000), &[], &Default::default(), &());
            println!(
                "{}",
                serde_json::json!({"sample":format!("synthetic-{count}"),"cfgMs":started.elapsed().as_secs_f64()*1000.0,"cfgInstructions":a.instructions.len()})
            );
            benchmark(&format!("synthetic-{count}"), &image, 64, &a, repetitions);
        }
    } else {
        let path = Path::new(args.get(1).expect("binary path or synthetic"));
        let name = path.file_name().unwrap().to_str().unwrap();
        let started = Instant::now();
        let b = ura_core::analyze_path(path).unwrap();
        let open = started.elapsed().as_secs_f64() * 1000.0;
        let started = Instant::now();
        let a = ura_core::analyze_functions(&b, &Default::default(), &());
        println!(
            "{}",
            serde_json::json!({"sample":name,"openMs":open,"cfgMs":started.elapsed().as_secs_f64()*1000.0,"cfgInstructions":a.instructions.len(),"cfgFunctions":a.functions.len(),"cfgPartial":a.report.truncated||a.report.cancelled})
        );
        benchmark(
            name,
            &CodeImage::from_binary(&b),
            b.analysis().bitness,
            &a,
            repetitions,
        );
    }
}
