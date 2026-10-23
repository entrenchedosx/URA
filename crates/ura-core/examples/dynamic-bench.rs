//! Reproducible Release microbenchmarks; never launches a native target.
use serde_json::json;
use std::{sync::atomic::AtomicBool, time::Instant};
use ura_core::{
    dynamic::{cpu::*, image::*, memory::*, replay::Replay},
    ir::Address,
};
fn ms(s: Instant) -> f64 {
    s.elapsed().as_secs_f64() * 1000.0
}
fn main() {
    let mut cfg = Config::default();
    cfg.limits.milliseconds = 10000;
    cfg.limits.events = 10000;
    cfg.limits.trace_bytes = 4 * 1024 * 1024;
    cfg.mappings.push(Mapping {
        base: Address(0x1000),
        bytes: vec![0xff, 0xc0, 0xeb, 0xfc],
        size: 4,
        permissions: Permissions::RX,
    });
    let mut cpu = Emulator::new(cfg).unwrap();
    let start = Instant::now();
    let state = cpu.run(10000, None, &AtomicBool::new(false), |_| {});
    let emulation_ms = ms(start);
    assert_eq!(state.instructions, 10000);
    let start = Instant::now();
    let id = cpu.save().unwrap();
    let snapshot_ms = ms(start);
    let start = Instant::now();
    for _ in 0..10000 {
        std::hint::black_box(cpu.memory.read(0x1000, 4).unwrap());
    }
    let reads_ms = ms(start);
    let trace = serde_json::to_vec(&cpu.export_trace()).unwrap();
    let start = Instant::now();
    let replay = Replay::load(&trace).unwrap();
    let load_ms = ms(start);
    let start = Instant::now();
    for n in 0..1000 {
        std::hint::black_box(replay.state((n * 997) % 10000, None).unwrap());
    }
    let seek_ms = ms(start);
    let code = vec![0xb8, 42, 0, 0, 0, 0xc3];
    let image = Image {
        format: "ura-memory-image".into(),
        schema_version: 1,
        bitness: 64,
        provenance: "owned benchmark raw code".into(),
        segments: vec![Segment {
            base: Address(0x1000),
            bytes: code.clone(),
            permissions: Permissions::RX,
        }],
        missing: vec![],
        original_sha256: Some(ura_core::sha256_hex(&code)),
        capture_metadata: None,
    };
    let start = Instant::now();
    let analyzed = image.analyze(0x1000).unwrap();
    let image_ms = ms(start);
    assert!(analyzed["pseudocode"].is_object());
    cpu.restore(Some(id)).unwrap();
    // Overlay uses captured module identity and actual static branch decoding.
    let binary = ura_core::binary::analyze_raw_bytes(
        std::path::Path::new("loop.raw"),
        vec![0xeb, 0xfe],
        Some(0x1000),
        64,
    )
    .unwrap();
    let analysis = ura_core::analyze_functions(&binary, &Default::default(), &());
    let hash = ura_core::sha256_hex(binary.bytes());
    let events=(1..=10000).map(|n|json!({"sequence":n,"session":"benchmark","pid":1,"thread":1,"kind":"instruction","address":"0x8000","module":{"base":"0x8000","size":2,"rva":"0x0","sha256":hash},"detail":{"changedRegisters":{}}})).collect::<Vec<_>>();
    let observed=Replay::load(&serde_json::to_vec(&json!({"format":"ura-observed-trace","schemaVersion":1,"session":"benchmark","pid":1,"events":events})).unwrap()).unwrap();
    let start = Instant::now();
    let overlay = observed.overlay(&analysis, &hash, 0x1000).unwrap();
    let overlay_ms = ms(start);
    assert_eq!(overlay["transitionCount"], 9999);
    println!(
        "{}",
        json!({"version":env!("CARGO_PKG_VERSION"),"profile":"release","instructions":state.instructions,"emulationMs":emulation_ms,"instructionsPerSecond":10000000.0/emulation_ms,"microsecondsPerInstruction":emulation_ms/10.0,"decodeCache":"none; re-decode each instruction for self-modifying correctness","fourByteReadNs":reads_ms*100.0,"snapshotMs":snapshot_ms,"snapshotStorage":"COW shared until write; four snapshots maximum; allocatedBytes excludes historical COW copies","allocatedBytes":state.allocated_bytes,"traceBytes":trace.len(),"replayEvents":10000,"replayLoadMs":load_ms,"averageSeekMs":seek_ms/1000.0,"seekSamples":1000,"overlay10000EventsMs":overlay_ms,"overlayRetainedTransitions":512,"imageAnalysis6BytesMs":image_ms,"nativeDesktopLaunched":false})
    );
}
