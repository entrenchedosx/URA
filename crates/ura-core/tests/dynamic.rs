use serde_json::json;
use std::{collections::BTreeMap, sync::atomic::AtomicBool};
use ura_core::dynamic::{cpu::*, image::*, memory::*, replay::*};
use ura_core::ir::Address;
fn emulator(code: &[u8], bits: u8, regs: &[(&str, u64)]) -> Emulator {
    Emulator::new(Config {
        bitness: bits,
        entry: Address(0x1000),
        registers: regs
            .iter()
            .map(|(k, v)| (k.to_string(), Address(*v)))
            .collect(),
        mappings: vec![Mapping {
            base: Address(0x1000),
            bytes: code.into(),
            size: code.len(),
            permissions: Permissions::RX,
        }],
        ..Default::default()
    })
    .unwrap()
}
fn run(e: &mut Emulator, n: u64) -> State {
    e.run(n, None, &AtomicBool::new(false), |_| {})
}
fn value(s: &State, key: &str) -> Option<u64> {
    s.registers[key].map(|a| a.0)
}
#[test]
fn real_machine_loop_flags_and_root_return_both_modes() {
    for bits in [32, 64] {
        let mut e = emulator(
            &[
                0x31, 0xc0, 0xb9, 3, 0, 0, 0, 0x83, 0xc0, 2, 0x83, 0xe9, 1, 0x75, 0xf8, 0xc3,
            ],
            bits,
            &[],
        );
        let s = run(&mut e, 100);
        assert_eq!(s.status, "returned");
        assert_eq!(value(&s, if bits == 64 { "rax" } else { "eax" }), Some(6));
        assert_eq!(s.instructions, 12);
        assert_eq!(value(&s, "zf"), Some(1));
    }
}
#[test]
fn nested_call_stack_executes_callee_then_returns() {
    for bits in [32, 64] {
        let mut e = emulator(
            &[
                0xb8, 5, 0, 0, 0, 0xe8, 1, 0, 0, 0, 0xc3, 0x83, 0xc0, 2, 0xc3,
            ],
            bits,
            &[],
        );
        let s = run(&mut e, 100);
        assert_eq!(s.status, "returned");
        assert_eq!(value(&s, if bits == 64 { "rax" } else { "eax" }), Some(7));
        assert_eq!(s.call_depth, 0);
        assert_eq!(s.instructions, 5);
    }
}
#[test]
fn aliases_zero_extension_and_inc_preserve_carry() {
    let mut e = emulator(
        &[
            0xb8, 0xff, 0xff, 0xff, 0xff, 0x04, 1, 0xfe, 0xc0, 0x0f, 0x92, 0xc1, 0xc3,
        ],
        64,
        &[("rax", u64::MAX)],
    );
    let s = run(&mut e, 100);
    assert_eq!(value(&s, "rax"), Some(0xffffff01));
    assert_eq!(value(&s, "rcx"), Some(1));
    assert_eq!(value(&s, "cf"), Some(1));
}
#[test]
fn shifts_match_independent_host_arithmetic_and_count_masks() {
    for (opcode, which) in [(0xe0, 0), (0xe8, 1), (0xf8, 2)] {
        for input in [0, 1, 0x55, 0x80, 0xff] {
            for count in 0..=255u64 {
                let mut e = emulator(
                    &[0xd2, opcode],
                    64,
                    &[
                        ("rax", input),
                        ("rcx", count),
                        ("cf", 1),
                        ("of", 1),
                        ("af", 1),
                    ],
                );
                let s = run(&mut e, 1);
                let c = (count & 31) as u32;
                let expected = match which {
                    0 => (input as u8).checked_shl(c).unwrap_or(0),
                    1 => (input as u8).checked_shr(c).unwrap_or(0),
                    _ => (input as i8).wrapping_shr(c.min(7)) as u8,
                };
                assert_eq!(
                    value(&s, "rax"),
                    Some(u64::from(expected)),
                    "op={opcode:x},input={input},count={count}"
                );
                if c == 0 {
                    assert_eq!(value(&s, "cf"), Some(1));
                    assert_eq!(value(&s, "of"), Some(1));
                    assert_eq!(value(&s, "af"), Some(1));
                } else {
                    assert_eq!(value(&s, "af"), None);
                    if c > 1 {
                        assert_eq!(value(&s, "of"), None);
                    }
                }
            }
        }
    }
}
#[test]
fn call_displacement66_is_data_and_address_override_wraps() {
    let mut code = vec![0x90; 113];
    code[..6].copy_from_slice(&[0xe8, 0x66, 0, 0, 0, 0xc3]);
    code[107..113].copy_from_slice(&[0xb8, 42, 0, 0, 0, 0xc3]);
    let mut e = emulator(&code, 32, &[]);
    let s = run(&mut e, 100);
    assert_eq!(s.status, "returned");
    assert_eq!(value(&s, "eax"), Some(42));
    let mut cfg = Config {
        registers: BTreeMap::from([
            ("rax".into(), Address(0xfffffffc)),
            ("rcx".into(), Address(4)),
        ]),
        mappings: vec![
            Mapping {
                base: Address(0x1000),
                bytes: vec![0x67, 0xff, 0x54, 8, 8, 0xc3],
                size: 6,
                permissions: Permissions::RX,
            },
            Mapping {
                base: Address(8),
                bytes: 0x1100u64.to_le_bytes().to_vec(),
                size: 8,
                permissions: Permissions::RW,
            },
            Mapping {
                base: Address(0x1100),
                bytes: vec![0xb8, 7, 0, 0, 0, 0xc3],
                size: 6,
                permissions: Permissions::RX,
            },
        ],
        ..Default::default()
    };
    let mut e = Emulator::new(cfg.clone()).unwrap();
    assert_eq!(value(&run(&mut e, 100), "rax"), Some(7));
    cfg.bitness = 32;
    cfg.registers.clear();
    cfg.registers.insert("ss_base".into(), Address(0x100));
    assert!(Emulator::new(cfg).is_err());
}
#[test]
fn faulting_rmw_does_not_commit_registers_flags_or_memory() {
    let mut e = Emulator::new(Config {
        registers: BTreeMap::from([("rsp".into(), Address(0x3000)), ("zf".into(), Address(1))]),
        mappings: vec![
            Mapping {
                base: Address(0x1000),
                bytes: vec![0x48, 0x83, 0x04, 0x24, 1],
                size: 5,
                permissions: Permissions::RX,
            },
            Mapping {
                base: Address(0x3000),
                bytes: vec![0; 8],
                size: 8,
                permissions: Permissions::RX,
            },
        ],
        ..Default::default()
    })
    .unwrap();
    let before = e.state().registers;
    let s = run(&mut e, 1);
    assert_eq!(s.status, "faulted");
    assert_eq!(s.fault.unwrap().kind, "permission");
    assert_eq!(s.instructions, 0);
    assert_eq!(s.registers, before);
    assert_eq!(e.memory.read(0x3000, 8).unwrap(), vec![0; 8]);
}
#[test]
fn division_fault_unknown_flags_and_unsupported_are_explicit() {
    for code in [
        &[0x31, 0xc9, 0xf7, 0xf1][..],
        &[0x0f, 0x05][..],
        &[0x0f, 0x0b][..],
    ] {
        let mut e = emulator(code, 64, &[]);
        let s = run(&mut e, 10);
        assert_eq!(s.status, "faulted");
        assert!(s.fault.is_some());
    }
    let mut e = emulator(&[0xd0, 0xe0, 0x72, 0], 64, &[("rax", 1)]);
    assert_eq!(run(&mut e, 1).registers["cf"], Some(Address(0)));
}
#[test]
fn self_modifying_code_is_fetched_from_current_virtual_bytes() {
    let mut cfg = Config {
        mappings: vec![Mapping {
            base: Address(0x1000),
            bytes: vec![0xc6, 5, 1, 0, 0, 0, 42, 0xb0, 1, 0xc3],
            size: 10,
            permissions: Permissions {
                read: true,
                write: true,
                execute: true,
            },
        }],
        ..Default::default()
    };
    let mut e = Emulator::new(cfg.clone()).unwrap();
    let id = e.save().unwrap();
    assert_eq!(value(&run(&mut e, 10), "rax"), Some(42));
    assert_eq!(e.memory.read(0x1008, 1).unwrap(), [42]);
    e.restore(Some(id)).unwrap();
    assert_eq!(e.memory.read(0x1008, 1).unwrap(), [1]);
    e.restore(None).unwrap();
    assert_eq!(e.state().instructions, 0);
    cfg.mappings[0].permissions.write = false;
    assert_eq!(
        run(&mut Emulator::new(cfg).unwrap(), 10)
            .fault
            .unwrap()
            .kind,
        "permission"
    );
}
#[test]
fn unmapped_nx_overflow_overlap_and_allocation_limits() {
    let mut m = Memory::new(32, 65536).unwrap();
    m.map(0xfffffff0, 16, &[1], Permissions::RW, "last page")
        .unwrap();
    assert!(m
        .map(0xffffffff, 2, &[], Permissions::RW, "overflow")
        .is_err());
    assert!(m
        .map(0xfffffff0, 1, &[], Permissions::RW, "overlap")
        .is_err());
    assert!(m.read(0, 1).is_err());
    assert!(m.map(0, 65536, &[], Permissions::RW, "overbudget").is_err());
    assert_eq!(m.read(0xfffffff0, 2).unwrap(), [1, 0]);
    let mut cfg = Config::default();
    cfg.mappings.push(Mapping {
        base: Address(0x1000),
        bytes: vec![0xc3],
        size: 1,
        permissions: Permissions::RW,
    });
    assert!(Emulator::new(cfg).is_err());
}
#[test]
fn instruction_call_depth_time_cancel_and_trace_budgets() {
    let mut e = emulator(&[0xeb, 0xfe], 64, &[]);
    e.config.limits.instructions = 5;
    e.config.limits.events = 2;
    let s = run(&mut e, 100);
    assert_eq!(s.instructions, 5);
    assert_eq!(s.stop_reason, "instructionLimit");
    assert_eq!(s.retained_events, 2);
    assert_eq!(s.dropped_events, 3);
    let mut e = emulator(&[0xeb, 0xfe], 64, &[]);
    assert_eq!(
        e.run(100, None, &AtomicBool::new(true), |_| {}).stop_reason,
        "cancelled"
    );
    assert_eq!(e.state().instructions, 0);
    e.config.limits.milliseconds = 1;
    assert_eq!(run(&mut e, 1000000).stop_reason, "durationLimit");
    let mut e = emulator(&[0xe8, 0xfb, 0xff, 0xff, 0xff], 64, &[]);
    e.config.limits.call_depth = 2;
    assert_eq!(run(&mut e, 20).fault.unwrap().kind, "callDepth");
}
#[test]
fn external_calls_stop_without_host_execution_or_use_explicit_return_model() {
    let code = [0xe8, 0xfb, 0x0f, 0, 0, 0xc3];
    let mut e = emulator(&code, 64, &[]);
    let s = run(&mut e, 20);
    assert_eq!(s.fault.unwrap().kind, "externalCall");
    assert_eq!(s.instructions, 0);
    let mut e = emulator(&code, 64, &[]);
    e.config
        .external_returns
        .insert(Address(0x2000), Address(42));
    assert_eq!(value(&run(&mut e, 20), "rax"), Some(42));
    assert!(e
        .export_trace()
        .to_string()
        .contains("AssumedExternalReturn"));
}
#[test]
fn emulated_breakpoints_run_to_and_reset_are_real_controls() {
    let mut e = emulator(&[0x90, 0x90, 0xc3], 64, &[]);
    e.breakpoints.insert(0x1001);
    let s = run(&mut e, 10);
    assert_eq!(s.stop_reason, "breakpoint");
    assert_eq!(s.instructions, 1);
    assert_eq!(run(&mut e, 10).status, "returned");
    e.restore(None).unwrap();
    assert_eq!(
        e.run(10, Some(0x1000), &AtomicBool::new(false), |_| {})
            .instructions,
        0
    );
}
fn observed(seq: u64, thread: u32, ip: u64, changes: serde_json::Value) -> serde_json::Value {
    json!({"sequence":seq,"session":"s","pid":7,"thread":thread,"kind":"instruction","address":format!("0x{ip:X}"),"module":null,"detail":{"changedRegisters":changes}})
}
fn replay(events: Vec<serde_json::Value>) -> Replay {
    Replay::load(&serde_json::to_vec(&json!({"format":"ura-observed-trace","schemaVersion":1,"session":"s","pid":7,"summary":{"dropped":0},"events":events})).unwrap()).unwrap()
}
#[test]
fn replay_seek_checkpoints_threads_gaps_and_missing_memory() {
    let events = (1..=300)
        .map(|n| observed(n, 1, 0x1000, json!({"rax":format!("0x{n:X}")})))
        .collect();
    let r = replay(events);
    assert_eq!(r.state(299, None).unwrap()["registers"]["rax"], "0x12C");
    assert_eq!(r.state(127, None).unwrap()["registers"]["rax"], "0x80");
    assert_eq!(r.state(0, None).unwrap()["memoryAvailable"], false);
    let r = replay(vec![
        observed(1, 1, 0x1000, json!({"rax":"0x1"})),
        observed(2, 2, 0x1000, json!({"rax":"0x2"})),
        observed(4, 1, 0x1000, json!({"rcx":"0x3"})),
    ]);
    let state = r.state(2, Some(1)).unwrap();
    assert!(state["registers"]["rax"].is_null());
    assert_eq!(state["registers"]["rcx"], "0x3");
    assert_eq!(r.state(2, Some(2)).unwrap()["discontinuous"], true);
}
#[test]
fn malformed_trace_order_identity_addresses_and_versions_reject() {
    for events in [
        vec![observed(2, 1, 1, json!({})), observed(1, 1, 1, json!({}))],
        vec![
            json!({"sequence":1,"session":"wrong","pid":7,"thread":1,"kind":"instruction","address":"0x1"}),
        ],
    ] {
        assert!(Replay::load(&serde_json::to_vec(&json!({"format":"ura-observed-trace","schemaVersion":1,"session":"s","pid":7,"events":events})).unwrap()).is_err());
    }
    assert!(Replay::load(b"{\"format\":\"ura-observed-trace\",\"schemaVersion\":2}").is_err());
}
#[test]
fn emulation_trace_replay_reports_post_instruction_timing() {
    let mut e = emulator(&[0xb8, 42, 0, 0, 0, 0xc3], 64, &[]);
    run(&mut e, 10);
    let r = Replay::load(&serde_json::to_vec(&e.export_trace()).unwrap()).unwrap();
    let s = r.state(0, None).unwrap();
    assert_eq!(s["registers"]["rax"], "0x2A");
    assert_eq!(s["instructionPointer"], "0x1005");
    assert_eq!(s["sourceMode"], "emulated");
}
#[test]
fn sparse_snapshot_image_preserves_holes_hash_permissions_and_analysis() {
    let code = vec![0xb8, 42, 0, 0, 0, 0xc3];
    let snapshot = json!({"format":"ura-memory-snapshot","schemaVersion":1,"address":"0x1000","requested":10,"captured":6,"missing":4,"capturedBytesSha256":ura_core::sha256_hex(&code),"chunks":[{"address":"0x1000","requested":10,"bytes":code,"missing":4,"region":{"protection":0x20}}]});
    let image = Image::load(&serde_json::to_vec(&snapshot).unwrap()).unwrap();
    assert_eq!(image.missing, vec![(Address(0x1006), 4)]);
    assert!(image.read(0x1006, 1).is_err());
    let analysis = image.analyze(0x1000).unwrap();
    assert!(analysis["ir"].is_object());
    assert!(analysis["pseudocode"].is_object(), "{analysis}");
    assert_eq!(analysis["portableExecutableReconstructed"], false);
    let encoded = serde_json::to_vec(&image).unwrap();
    let other = Image::load(&encoded).unwrap();
    assert_eq!(
        image.compare(&other, 0x1000, 10).unwrap()["unknownBytes"],
        4
    );
    let mut bad = snapshot;
    bad["capturedBytesSha256"] = json!("0".repeat(64));
    assert!(Image::load(&serde_json::to_vec(&bad).unwrap()).is_err());
}
#[test]
fn executable_images_use_real_file_addresses_without_rebasing() {
    for name in ["ura64.exe", "ura64.elf"] {
        let file = ura_core::analyze_path(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures")
                .join(name),
        )
        .unwrap();
        let image = Image::from_binary(&file).unwrap();
        assert_eq!(
            image.original_sha256,
            Some(ura_core::sha256_hex(file.bytes()))
        );
        let executable = file
            .analysis()
            .sections
            .iter()
            .find(|s| s.executable)
            .unwrap();
        assert_eq!(
            image.read(executable.address, 4).unwrap(),
            file.bytes()[executable.file_offset.unwrap() as usize..][..4]
        );
    }
}

#[test]
fn replay_cross_thread_ip_and_import_validation() {
    let r = replay(vec![
        observed(1, 1, 0x1111, json!({"rax":"0x1"})),
        observed(2, 2, 0x2222, json!({"rax":"0x2"})),
    ]);
    let state = r.state(1, Some(1)).unwrap();
    assert_eq!(state["instructionPointer"], "0x1111");
    assert_eq!(state["selectedEventAddress"], "0x2222");
    assert_eq!(state["capturedAtSequence"], 1);
    for v in [
        json!({"format":"ura-observed-trace","schemaVersion":1,"events":[{"sequence":1,"thread":1,"kind":"instruction","address":"0x1"}]}),
        json!({"format":"ura-emulation-trace","schemaVersion":1,"events":[{"sequence":1,"address":"0x1","nextAddress":"garbage","changedRegisters":{}}]}),
        json!({"format":"ura-emulation-trace","schemaVersion":1,"bitness":32,"events":[{"sequence":1,"address":"0x1","nextAddress":"0x100000000","changedRegisters":{}}]}),
    ] {
        assert!(Replay::load(&serde_json::to_vec(&v).unwrap()).is_err());
    }
}
#[test]
fn overlay_requires_identity_and_reports_transition_truncation() {
    let code = vec![0xeb, 0xfe];
    let binary = ura_core::binary::analyze_raw_bytes(
        std::path::Path::new("loop.raw"),
        code.clone(),
        Some(0x1000),
        64,
    )
    .unwrap();
    let analysis = ura_core::analyze_image(
        &ura_core::CodeImage::from_binary(&binary),
        64,
        Some(0x1000),
        &[],
        &Default::default(),
        &(),
    );
    let hash = ura_core::sha256_hex(&code);
    let mut events = vec![];
    for n in 1..=601 {
        let mut event = observed(n, 1, 0x8000, json!({}));
        event["module"] = json!({"base":"0x8000","rva":"0x0","size":2,"sha256":hash});
        events.push(event);
    }
    let replay = replay(events);
    let overlay = replay.overlay(&analysis, &hash, 0x1000).unwrap();
    assert_eq!(overlay["transitionCount"], 600);
    assert_eq!(overlay["retainedTransitions"], 512);
    assert_eq!(overlay["transitionsTruncated"], true);
    assert_eq!(overlay["blockInstructionObservations"]["0x1000"], 601);
    assert_eq!(overlay["transitions"][0]["existsInStatic"], true);
    assert_eq!(
        replay.overlay(&analysis, &"0".repeat(64), 0x1000).unwrap()
            ["unmappedInstructionObservations"],
        601
    );
}
#[test]
fn native_loader_rejects_non_x86_even_when_bitness_matches() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/ura64.elf");
    let mut bytes = std::fs::read(path).unwrap();
    bytes[18..20].copy_from_slice(&183u16.to_le_bytes()); // EM_AARCH64, valid ELF64
    let binary = ura_core::binary::analyze_bytes(std::path::Path::new("arm64.elf"), bytes).unwrap();
    assert_eq!(binary.analysis().bitness, 64);
    assert_eq!(Image::from_binary(&binary).unwrap_err().kind, "loader");
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn compiler_generated_owned_fixture_matches_real_cpu_results() {
    use std::{os::windows::process::CommandExt, process::Command};
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let folder = root.join("target/emulation-reference");
    std::fs::create_dir_all(&folder).unwrap();
    let exe = folder.join(format!("reference-{}.exe", std::process::id()));
    let compile = Command::new("rustc")
        .args([
            "--edition=2021",
            "-C",
            "opt-level=2",
            "-C",
            "link-arg=/EXPORT:ura_emu_math",
        ])
        .arg(root.join("tests/fixtures/emulation-reference.rs"))
        .arg("-o")
        .arg(&exe)
        .creation_flags(0x08000000)
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let native = Command::new(&exe)
        .creation_flags(0x08000000)
        .output()
        .unwrap();
    assert!(native.status.success());
    let binary = ura_core::analyze_path(&exe).unwrap();
    let entry = binary
        .analysis()
        .exports
        .iter()
        .find(|s| s.name == "ura_emu_math")
        .unwrap()
        .address;
    let image = Image::from_binary(&binary).unwrap();
    for line in String::from_utf8(native.stdout).unwrap().lines() {
        let fields = line
            .split_whitespace()
            .map(|n| n.parse::<u64>().unwrap())
            .collect::<Vec<_>>();
        let mut cfg = Config::default();
        cfg.registers.insert("rcx".into(), Address(fields[0]));
        cfg.registers.insert("rdx".into(), Address(fields[1]));
        let mut cpu = Emulator::new(image.config(entry, cfg).unwrap()).unwrap();
        let state = run(&mut cpu, 100);
        assert_eq!(state.status, "returned", "{:?}", state.fault);
        assert_eq!(value(&state, "rax"), Some(fields[2]), "{line}");
    }
}
