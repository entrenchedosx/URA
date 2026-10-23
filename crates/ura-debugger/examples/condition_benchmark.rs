//! Release CPU-only predicate samples; no process execution or UI.
use std::{hint::black_box, time::Instant};
use ura_debugger::{Condition, Registers};
fn main() {
    let registers = Registers {
        thread: 1,
        architecture: "windows-x64".into(),
        values: [
            ("rcx".into(), "0x2".into()),
            ("rsp".into(), "0x100000".into()),
        ]
        .into(),
    };
    let condition = Condition::parse("(ecx & 3) == 2 && rsp > 0x10000").unwrap();
    let mut samples = Vec::new();
    for _ in 0..5 {
        let started = Instant::now();
        let mut matched = 0;
        for _ in 0..100000 {
            matched += usize::from(
                black_box(&condition)
                    .evaluate(black_box(&registers))
                    .unwrap(),
            );
        }
        assert_eq!(matched, 100000);
        samples.push(started.elapsed().as_secs_f64() * 1e9 / 100000.0);
    }
    println!(
        "{}",
        serde_json::json!({"iterationsPerRun":100000,"runs":5,"nanosecondsPerEvaluation":samples,"scope":"compiled predicate over captured registers; excludes Windows breakpoint and transport overhead"})
    );
}
