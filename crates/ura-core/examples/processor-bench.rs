//! Release-only, headless cross-processor pipeline and cancellation measurements.
use serde_json::json;
use std::{path::Path, sync::atomic::AtomicBool, time::Instant};
use ura_core::{
    binary,
    dynamic::{cpu::*, memory::Permissions},
    ir,
    processor::{self, Processor},
};
fn elapsed(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}
fn main() {
    if cfg!(debug_assertions) {
        panic!("use --release");
    }
    let mut rows = vec![];
    for p in [
        Processor::X86_64,
        Processor::Aarch64,
        Processor::Arm,
        Processor::Thumb,
        Processor::Riscv32,
        Processor::Riscv64,
    ] {
        let path = if p == Processor::X86_64 {
            "tests/fixtures/ura64.elf".into()
        } else {
            format!("tests/fixtures/processors/{}-O1.elf", p.name())
        };
        let b = binary::analyze_path(Path::new(&path)).unwrap();
        let t = Instant::now();
        let a = ura_core::analyze_functions(&b, &Default::default(), &());
        let cfg_ms = elapsed(t);
        let entry = if p.x86() {
            a.functions[0].address
        } else {
            b.analysis()
                .symbols
                .iter()
                .find(|s| s.name == "ura_nested")
                .unwrap()
                .address
                .unwrap()
                & !1
        };
        let t = Instant::now();
        let raw = ir::lift_function(&b, &a, entry, &()).unwrap();
        let lift_ms = elapsed(t);
        let t = Instant::now();
        let ssa = ir::ssa::construct(&raw).unwrap();
        let ssa_ms = elapsed(t);
        let t = Instant::now();
        let data = ir::dataflow::analyze(&ssa).unwrap();
        let dataflow_ms = elapsed(t);
        let t = Instant::now();
        let decomp = ura_core::decomp::analyze_function(
            &b,
            &a,
            entry,
            &ura_core::decomp::DecompContext::new(u16::from(p.bits())),
            &(),
        )
        .unwrap();
        let decompile_ms = elapsed(t);
        let mut decode_ms = None;
        if !p.x86() {
            let t = Instant::now();
            for _ in 0..10 {
                for inst in a.instructions.values() {
                    let bytes = b
                        .bytes_at_address(inst.address, usize::from(inst.length))
                        .unwrap();
                    std::hint::black_box(processor::decode(p, bytes, inst.address).unwrap());
                }
            }
            decode_ms = Some(elapsed(t) / 10.0);
        }
        let code = match p {
            Processor::X86_64 => vec![0xeb, 0xfe],
            Processor::Aarch64 => 0x14000000u32.to_le_bytes().to_vec(),
            Processor::Arm => 0xeafffffeu32.to_le_bytes().to_vec(),
            Processor::Thumb => 0xe7feu16.to_le_bytes().to_vec(),
            _ => 0x0000006fu32.to_le_bytes().to_vec(),
        };
        let mut config = Config {
            processor: Some(p),
            bitness: p.bits(),
            ..Default::default()
        };
        config.limits.milliseconds = 10000;
        config.limits.events = 1;
        config.mappings.push(Mapping {
            base: ir::Address(0x1000),
            bytes: code.clone(),
            size: code.len(),
            permissions: Permissions::RX,
        });
        let mut cpu = Emulator::new(config).unwrap();
        let t = Instant::now();
        let state = cpu.run(10000, None, &AtomicBool::new(false), |_| {});
        let emulation_ms = elapsed(t);
        assert_eq!(state.instructions, 10000);
        let t = Instant::now();
        let cancelled = cpu.run(1000, None, &AtomicBool::new(true), |_| {});
        let cancel_ms = elapsed(t);
        assert_eq!(cancelled.instructions, 10000);
        rows.push(json!({"processor":p,"file":path,"instructions":a.instructions.len(),"decodeMs":decode_ms,"cfgMs":cfg_ms,"liftMs":lift_ms,"ssaMs":ssa_ms,"dataflowMs":dataflow_ms,"dataflowFacts":data.constants.len(),"decompileMs":decompile_ms,"pseudocodeLines":decomp.pseudocode.lines.len(),"emulate10000Ms":emulation_ms,"allocatedBackingBytes":state.allocated_bytes,"cancelAlreadyRequestedMs":cancel_ms}));
    }
    let code = (0..2000)
        .flat_map(|_| 0x91000400u32.to_le_bytes())
        .chain(0xd65f03c0u32.to_le_bytes())
        .collect::<Vec<_>>();
    let b = binary::analyze_raw_processor_bytes(
        Path::new("large.raw"),
        code,
        Some(0x1000),
        Processor::Aarch64,
    )
    .unwrap();
    let t = Instant::now();
    let a = ura_core::analyze_functions(&b, &Default::default(), &());
    let cfg_ms = elapsed(t);
    let t = Instant::now();
    let d = ura_core::decomp::analyze_function(
        &b,
        &a,
        0x1000,
        &ura_core::decomp::DecompContext::new(64),
        &(),
    )
    .unwrap();
    let decompile_ms = elapsed(t);
    println!(
        "{}",
        json!({"version":env!("CARGO_PKG_VERSION"),"profile":"release","samplesPerPipeline":1,"decodeIterations":10,"rows":rows,"largeArm64":{"instructions":a.instructions.len(),"cfgMs":cfg_ms,"decompileMs":decompile_ms,"pseudocodeLines":d.pseudocode.lines.len()},"memoryScope":"mapped emulator backing bytes; not total process RSS or Capstone allocations","cancelScope":"latency with cancellation already set; async service stop measured separately","foreignHostExecution":false,"desktopLaunched":false})
    );
}
