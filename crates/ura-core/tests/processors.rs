use std::{
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};
use ura_core::{
    binary,
    dynamic::{cpu::*, image::Image, memory::Permissions},
    ir::{self, Address},
    processor::{self, Processor},
    AnalysisControl,
};
fn fixture(p: Processor, opt: u8) -> ura_core::LoadedBinary {
    let name = p.name();
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../../tests/fixtures/processors/{name}-O{opt}.elf"));
    binary::analyze_path(&path).unwrap()
}
fn entry(b: &ura_core::LoadedBinary, name: &str) -> u64 {
    b.analysis()
        .symbols
        .iter()
        .find(|s| s.name == name)
        .unwrap()
        .address
        .unwrap()
        & !1
}
fn run_fixture(p: Processor, opt: u8, symbol: &str, a: u64, b: u64) -> State {
    let binary = fixture(p, opt);
    let image = Image::from_binary(&binary).unwrap();
    let args = match p {
        Processor::Aarch64 => ["x0", "x1"],
        Processor::Arm | Processor::Thumb => ["r0", "r1"],
        _ => ["a0", "a1"],
    };
    let mut cfg = Config::default();
    cfg.limits.milliseconds = 10000;
    cfg.registers
        .insert(args[0].into(), Address(a & ir::mask(u16::from(p.bits()))));
    cfg.registers
        .insert(args[1].into(), Address(b & ir::mask(u16::from(p.bits()))));
    let mut cpu = Emulator::new(image.config(entry(&binary, symbol), cfg).unwrap()).unwrap();
    cpu.run(10000, None, &AtomicBool::new(false), |_| {})
}
fn raw(p: Processor, bytes: &[u8], regs: &[(&str, u64)], data: bool) -> Emulator {
    let mut cfg = Config {
        processor: Some(p),
        bitness: p.bits(),
        ..Default::default()
    };
    cfg.mappings.push(Mapping {
        base: Address(0x1000),
        bytes: bytes.into(),
        size: bytes.len(),
        permissions: Permissions::RX,
    });
    if data {
        cfg.mappings.push(Mapping {
            base: Address(0x2000),
            bytes: vec![7, 0, 0, 0, 9, 0, 0, 0],
            size: 4096,
            permissions: Permissions::RW,
        });
    }
    for (name, value) in regs {
        cfg.registers.insert((*name).into(), Address(*value));
    }
    Emulator::new(cfg).unwrap()
}
fn words(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}
fn run(cpu: &mut Emulator) -> State {
    cpu.run(10000, None, &AtomicBool::new(false), |_| {})
}
#[test]
fn compiler_generated_scalar_stack_calls_and_data_use_real_processor_banks() {
    for p in [
        Processor::Aarch64,
        Processor::Arm,
        Processor::Thumb,
        Processor::Riscv32,
        Processor::Riscv64,
    ] {
        for opt in 0..4 {
            for (symbol, expected) in [
                ("ura_scalar", 64),
                ("ura_width", 12),
                ("ura_pointer", 7),
                ("ura_stack", 15),
                ("ura_nested", 69),
                ("ura_literal", 29),
            ] {
                let a = if symbol == "ura_pointer" {
                    0x70000000
                } else {
                    5
                };
                let b = 7;
                let s = run_fixture(p, opt, symbol, a, b);
                assert_eq!(s.status, "returned", "{p:?} O{opt} {symbol}: {s:?}");
                assert_eq!(
                    s.registers[p.result()].unwrap().0,
                    expected,
                    "{p:?} O{opt} {symbol}"
                );
                assert!(!s.registers.contains_key("rax"));
                assert_eq!(s.registers[p.stack()].unwrap().0, 0x70010000);
            }
        }
    }
}
#[test]
fn signed_conditions_and_loops_match_independent_scalar_results() {
    for p in [Processor::Aarch64, Processor::Riscv32, Processor::Riscv64] {
        for opt in 0..4 {
            for (a, b, expected) in [(5, 7, 12), (7, 5, u64::MAX - 3), (u64::MAX, 0, 6)] {
                let s = run_fixture(p, opt, "ura_select", a, b);
                assert_eq!(s.status, "returned");
                assert_eq!(
                    s.registers[p.result()].unwrap().0,
                    expected & ir::mask(u16::from(p.bits()))
                );
            }
            let mut expected = 5;
            for n in 0..7 {
                expected = (expected ^ n) + 3;
            }
            let s = run_fixture(p, opt, "ura_loop", 5, 7);
            assert_eq!(s.registers[p.result()].unwrap().0, expected);
        }
    }
}
#[test]
fn all_supported_fixture_functions_verify_ir_ssa_and_deterministic_source() {
    for p in [
        Processor::Aarch64,
        Processor::Arm,
        Processor::Thumb,
        Processor::Riscv32,
        Processor::Riscv64,
    ] {
        for opt in 0..4 {
            let binary = fixture(p, opt);
            let analysis = ura_core::analyze_functions(&binary, &Default::default(), &());
            for symbol in [
                "ura_scalar",
                "ura_width",
                "ura_pointer",
                "ura_stack",
                "ura_nested",
                "ura_literal",
            ] {
                let address = entry(&binary, symbol);
                let bundle = ir::inspect::analyze(&binary, &analysis, address, &()).unwrap();
                assert!(
                    bundle.raw.diagnostics.is_empty(),
                    "{p:?} O{opt} {symbol}: {:?}",
                    bundle.raw.diagnostics
                );
                ir::verify(&bundle.raw).unwrap();
                ir::ssa::verify_ssa(&bundle.ssa).unwrap();
                let context = ura_core::decomp::DecompContext::new(u16::from(p.bits()));
                let one =
                    ura_core::decomp::analyze_function(&binary, &analysis, address, &context, &())
                        .unwrap();
                let two =
                    ura_core::decomp::analyze_function(&binary, &analysis, address, &context, &())
                        .unwrap();
                assert_eq!(
                    serde_json::to_value(&one.pseudocode).unwrap(),
                    serde_json::to_value(&two.pseudocode).unwrap()
                );
                assert!(!one.pseudocode.lines.is_empty());
            }
        }
    }
}
#[test]
fn aarch64_word_alias_zero_extension_and_carry_have_no_x86_flags() {
    let code = words(&[0x2b010000, 0xd65f03c0]);
    let mut e = raw(
        Processor::Aarch64,
        &code,
        &[("x0", u64::MAX), ("x1", 1)],
        false,
    );
    let s = run(&mut e);
    assert_eq!(s.status, "returned");
    assert_eq!(s.registers["x0"], Some(Address(0)));
    assert_eq!(s.registers["c"], Some(Address(1)));
    assert_eq!(s.registers["z"], Some(Address(1)));
    assert_eq!(s.flags_known_mask, Address(0xf0000000));
    assert!(
        Emulator::new(Config {
            processor: Some(Processor::Aarch64),
            registers: [("w0".into(), Address(1))].into(),
            mappings: vec![Mapping {
                base: Address(0x1000),
                bytes: code.clone(),
                size: code.len(),
                permissions: Permissions::RX
            }],
            ..Default::default()
        })
        .is_err(),
        "initial state requires explicit canonical roots"
    );
}
#[test]
fn unsupported_vectors_syscalls_waits_and_mode_changes_stop_before_commit() {
    for (p, code) in [
        (Processor::Aarch64, words(&[0x1e612800])),
        (Processor::Aarch64, words(&[0xd4000001])),
        (Processor::Arm, words(&[0xe320f002])),
        (Processor::Thumb, vec![0x20, 0xbf]),
        (Processor::Riscv64, words(&[0x00000073])),
        (Processor::Thumb, vec![0x08, 0xbf]),
    ] {
        let mut e = raw(p, &code, &[], false);
        let before = e.state().registers;
        let s = run(&mut e);
        assert_eq!(s.status, "faulted", "{p:?}");
        assert_eq!(s.instructions, 0);
        assert_eq!(s.registers, before);
        assert_eq!(s.instruction_pointer, Address(0x1000));
        assert_eq!(s.fault.unwrap().kind, "unsupported");
    }
}
#[test]
fn arm_register_post_index_updates_the_base_without_touching_other_roots() {
    let mut e = raw(
        Processor::Arm,
        &words(&[0xe6910002, 0xe12fff1e]),
        &[("r1", 0x2000), ("r2", 4)],
        true,
    );
    let s = run(&mut e);
    assert_eq!(s.status, "returned");
    assert_eq!(s.registers["r0"], Some(Address(7)));
    assert_eq!(s.registers["r1"], Some(Address(0x2004)));
}
#[test]
fn traps_and_unsupported_pc_writes_end_cfg_discovery() {
    for (p, bytes) in [
        (Processor::Riscv64, vec![0x02, 0x90]),
        (Processor::Arm, words(&[0xe1a0f00e])),
    ] {
        let d = processor::decode(p, &bytes, 0x1000).unwrap();
        assert_eq!(d.flow, ura_core::InstructionFlow::Exception);
    }
}
#[test]
fn raw_processor_selection_alignment_bitness_and_image_conflicts_are_enforced() {
    let code = words(&[0xd503201f, 0xd65f03c0]);
    let b = binary::analyze_raw_processor_bytes(
        Path::new("a.raw"),
        code.clone(),
        Some(0x1000),
        Processor::Aarch64,
    )
    .unwrap();
    assert_eq!(
        Processor::for_analysis(b.analysis()).unwrap(),
        Processor::Aarch64
    );
    assert!(binary::analyze_raw_processor_bytes(
        Path::new("bad.raw"),
        code,
        Some(0x1001),
        Processor::Arm
    )
    .is_err());
    let image = Image::from_binary(&b).unwrap();
    assert!(image
        .config(
            0x1000,
            Config {
                processor: Some(Processor::X86_64),
                ..Default::default()
            }
        )
        .is_err());
    let b = fixture(Processor::Thumb, 1);
    let cfg = Image::from_binary(&b)
        .unwrap()
        .config(b.analysis().entry_point.unwrap(), Config::default())
        .unwrap();
    assert_eq!(cfg.entry.0 % 2, 0);
    assert!(Emulator::new(cfg).is_ok());
    let mut metadata = b.analysis().clone();
    metadata.entry_point = Some(0);
    assert_eq!(
        Processor::for_analysis(&metadata).unwrap(),
        Processor::Thumb
    );
    metadata.endianness = ura_core::Endianness::Big;
    assert!(Processor::for_analysis(&metadata).is_err());
}
#[test]
fn new_processor_unsupported_semantics_remain_barriers_in_static_ir() {
    let code = words(&[0x1e612800, 0xd65f03c0]);
    let b = binary::analyze_raw_processor_bytes(
        Path::new("vector.raw"),
        code,
        Some(0x1000),
        Processor::Aarch64,
    )
    .unwrap();
    let a = ura_core::analyze_functions(&b, &Default::default(), &());
    let f = ir::lift_function(&b, &a, 0x1000, &()).unwrap();
    assert!(!f.diagnostics.is_empty());
    assert!(f.blocks[0]
        .statements
        .iter()
        .any(|s| matches!(s.op, ir::Operation::Barrier { .. })));
}
struct Cancel;
impl AnalysisControl for Cancel {
    fn is_cancelled(&self) -> bool {
        true
    }
    fn report(&self, _: ura_core::AnalysisProgress) {}
}
#[test]
fn architecture_analysis_and_ir_obey_cancellation() {
    let b = fixture(Processor::Aarch64, 0);
    let a = ura_core::analyze_functions(&b, &Default::default(), &Cancel);
    assert!(a.report.cancelled);
    let a = ura_core::analyze_functions(&b, &Default::default(), &());
    assert!(ir::lift_function(&b, &a, entry(&b, "ura_stack"), &Cancel).is_err());
    let mut cpu = raw(Processor::Riscv64, &words(&[0x0000006f]), &[], false);
    let s = cpu.run(100, None, &AtomicBool::new(true), |_| {});
    assert_eq!(s.instructions, 0);
}

#[test]
fn aarch64_constrained_alias_and_duplicate_loads_are_rejected_transactionally() {
    for word in [0xb8404400, 0xa9400020] {
        let mut e = raw(
            Processor::Aarch64,
            &words(&[word]),
            &[("x0", 0x2000), ("x1", 0x2000)],
            true,
        );
        let initial = e.state().registers;
        let s = run(&mut e);
        assert_eq!(s.status, "faulted");
        assert_eq!(s.instructions, 0);
        assert_eq!(s.registers, initial);
        assert_eq!(
            e.memory.read(0x2000, 8).unwrap(),
            vec![7, 0, 0, 0, 9, 0, 0, 0]
        );
    }
}
#[test]
fn arm_abi_aliases_are_canonical_and_caller_saved_ip_is_invalidated() {
    let d = processor::decode(Processor::Arm, &0xe1a0900au32.to_le_bytes(), 0x1000).unwrap();
    assert!(matches!(&d.args[0].value,processor::Arg::Reg(r)if r=="r9"));
    assert!(matches!(&d.args[1].value,processor::Arg::Reg(r)if r=="r10"));
    let binary = fixture(Processor::Arm, 1);
    let analysis = ura_core::analyze_functions(&binary, &Default::default(), &());
    let f = ir::lift_function(&binary, &analysis, entry(&binary, "ura_nested"), &()).unwrap();
    let ip = f.variables.iter().position(|v| v.name == "r12").unwrap();
    assert!(f
        .blocks
        .iter()
        .flat_map(|b| &b.statements)
        .any(|s| s.output == Some(ip) && matches!(s.op, ir::Operation::Unknown { .. })));
    for call in f
        .blocks
        .iter()
        .flat_map(|b| &b.statements)
        .filter(|s| s.op == ir::Operation::Call)
    {
        assert_eq!(
            call.args.len(),
            f.variables
                .iter()
                .filter(|v| v.kind != ir::VariableKind::Temporary)
                .count()
                + 1
        );
    }
}

#[test]
fn proven_scalar_stack_slots_saved_links_and_stack_arguments_have_real_offsets() {
    for p in [
        Processor::Aarch64,
        Processor::Arm,
        Processor::Thumb,
        Processor::Riscv32,
        Processor::Riscv64,
    ] {
        let b = fixture(p, 1);
        let a = ura_core::analyze_functions(&b, &Default::default(), &());
        let frame = ura_core::decomp::stack::recover(&b, &a, entry(&b, "ura_stack"), None).unwrap();
        assert!(frame.frame_size >= 12, "{p:?}: {frame:?}");
        assert_eq!(frame.slots.len(), 3, "{p:?}: {frame:?}");
        assert_eq!(frame.return_address_register.as_deref(), p.link());
        assert!(frame.slots.iter().all(|s| s.offset < 0));
        let frame =
            ura_core::decomp::stack::recover(&b, &a, entry(&b, "ura_nested"), None).unwrap();
        assert!(
            frame
                .saved_registers
                .iter()
                .any(|s| Some(s.as_str()) == p.link()),
            "{p:?}: {frame:?}"
        );
        let f = ura_core::decomp::analyze_function(
            &b,
            &a,
            entry(&b, "ura_stack_args"),
            &ura_core::decomp::DecompContext::new(u16::from(p.bits())),
            &(),
        )
        .unwrap();
        assert!(
            f.signature
                .parameters
                .iter()
                .any(|p| p.index == 8
                    && matches!(p.location, ura_core::decomp::Location::Stack { .. })),
            "{p:?}: {:?}",
            f.signature
        );
    }
}

#[test]
fn above_entry_stack_store_does_not_invent_an_incoming_argument_or_saved_local() {
    let b = binary::analyze_raw_processor_bytes(
        Path::new("above.raw"),
        words(&[0xf90003f3, 0xd65f03c0]),
        Some(0x1000),
        Processor::Aarch64,
    )
    .unwrap();
    let a = ura_core::analyze_functions(&b, &Default::default(), &());
    let f = ura_core::decomp::stack::recover(&b, &a, 0x1000, None).unwrap();
    assert_eq!(f.slots.len(), 1);
    assert_eq!(f.incoming_argument_bytes, 0);
    assert!(f.saved_registers.is_empty());
    assert_eq!(f.slots[0].kind, "aboveEntryStackAccess");
}
