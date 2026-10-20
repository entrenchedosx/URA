use std::{path::PathBuf, time::Instant};
fn main() {
    let mut results = Vec::new();
    for path in std::env::args_os().skip(1).map(PathBuf::from) {
        for run in 1..=3 {
            let started = Instant::now();
            let binary = ura_core::analyze_path(&path).expect("parse benchmark image");
            let parse_ms = started.elapsed().as_secs_f64() * 1000.0;
            let started = Instant::now();
            let info = binary.view();
            let identity_ms = started.elapsed().as_secs_f64() * 1000.0;
            let started = Instant::now();
            let analysis = ura_core::analyze_functions(&binary, &Default::default(), &());
            let analysis_ms = started.elapsed().as_secs_f64() * 1000.0;
            let started = Instant::now();
            let strings = binary.extract_strings(&Default::default()).unwrap();
            let strings_ms = started.elapsed().as_secs_f64() * 1000.0;
            let started = Instant::now();
            for f in analysis.functions.iter().take(100) {
                let _ = ura_native::graph::layout(&analysis, f.address);
            }
            let graph_layout_ms = started.elapsed().as_secs_f64() * 1000.0;
            results.push(serde_json::json!({ "file": binary.file_name(), "bytes": info.file_size, "sha256": info.sha256, "run": run, "parse_ms": parse_ms, "identity_ms": identity_ms, "analysis_ms": analysis_ms, "strings_ms": strings_ms, "graph_layout_first_100_functions_ms": graph_layout_ms, "functions": analysis.functions.len(), "instructions": analysis.instructions.len(), "strings": strings.strings.len(), "partial_analysis": analysis.report.cancelled || analysis.report.truncated, "partial_strings": strings.truncated }));
        }
    }
    println!("{}", serde_json::to_string_pretty(&results).unwrap());
}
