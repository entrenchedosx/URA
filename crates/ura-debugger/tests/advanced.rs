#![cfg(all(windows, target_arch = "x86_64"))]
use object::Object;
use std::time::{Duration, Instant};
use ura_debugger::*;
#[path = "../../../tests/support/debug_fixture.rs"]
mod fixture;
fn wait(c: &Controller, state: State) -> Snapshot {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let s = c.snapshot();
        if s.state == state {
            return s;
        }
        assert!(Instant::now() < deadline, "timeout: {s:#?}");
        std::thread::sleep(Duration::from_millis(2));
    }
}
fn launch() -> (Controller, Snapshot) {
    launch_args(&[])
}
fn launch_args(arguments: &[&str]) -> (Controller, Snapshot) {
    let c = Controller::new();
    c.command(
        None,
        Command::Launch(LaunchConfig {
            executable: fixture::fixture(),
            expected_sha256: None,
            arguments: arguments.iter().map(|s| s.to_string()).collect(),
            working_directory: None,
            environment: Default::default(),
            break_at_entry: true,
        }),
    )
    .unwrap();
    let s = wait(&c, State::Paused);
    (c, s)
}
fn export(s: &Snapshot, name: &str) -> u64 {
    let bytes = std::fs::read(fixture::fixture()).unwrap();
    let file = object::File::parse(bytes.as_slice()).unwrap();
    let export = file
        .exports()
        .unwrap()
        .into_iter()
        .find(|e| e.name() == name.as_bytes())
        .unwrap()
        .address();
    ura_core::parse_address(&s.modules[0].base).unwrap() + export - file.relative_address_base()
}
fn go(c: &Controller, s: &Snapshot) {
    c.command(
        s.session.as_deref(),
        Command::Continue {
            pass_exception: true,
        },
    )
    .unwrap();
}
fn kill(c: &Controller, s: &Snapshot) {
    c.command(s.session.as_deref(), Command::Terminate).unwrap();
    wait(c, State::Exited);
}
#[test]
fn actual_hardware_execution_slots_new_threads_removal_and_continuation() {
    let (c, s) = launch();
    let target = export(&s, "ura_marker");
    for n in 0..4 {
        let mut cfg = BreakpointConfig::software(target + n);
        cfg.kind = BreakpointKind::HardwareExecute;
        c.command(s.session.as_deref(), Command::ConfigureBreakpoint(cfg))
            .unwrap();
    }
    let mut cfg = BreakpointConfig::software(target + 4);
    cfg.kind = BreakpointKind::HardwareExecute;
    assert!(c
        .command(s.session.as_deref(), Command::ConfigureBreakpoint(cfg))
        .is_err());
    assert_eq!(c.snapshot().breakpoints.len(), 4);
    let points = c.snapshot().breakpoints;
    for p in &points[1..] {
        c.command(
            s.session.as_deref(),
            Command::Breakpoint {
                action: "remove".into(),
                address: None,
                id: Some(p.id),
            },
        )
        .unwrap();
    }
    go(&c, &s);
    let hit = wait(&c, State::Paused);
    assert_eq!(hit.reason.as_deref(), Some("hardwareBreakpoint"));
    assert_eq!(hit.registers.as_ref().unwrap().values["rcx"], "0x1");
    assert!(hit.breakpoints[0].threads.len() >= 2);
    go(&c, &s);
    let hit2 = wait(&c, State::Paused);
    assert_eq!(hit2.breakpoints[0].hits, 2);
    c.command(
        s.session.as_deref(),
        Command::Breakpoint {
            action: "remove".into(),
            address: None,
            id: Some(hit2.breakpoints[0].id),
        },
    )
    .unwrap();
    go(&c, &s);
    assert_eq!(wait(&c, State::Exited).exit_code, Some(42));
}
#[test]
fn actual_write_and_readwrite_watchpoints_and_alignment() {
    for kind in [BreakpointKind::Write, BreakpointKind::ReadWrite] {
        let (c, s) = launch();
        let target = export(&s, "ura_watch");
        let mut cfg = BreakpointConfig::software(target + 1);
        cfg.kind = kind;
        cfg.length = 8;
        assert!(c
            .command(
                s.session.as_deref(),
                Command::ConfigureBreakpoint(cfg.clone())
            )
            .is_err());
        cfg.address = target;
        c.command(s.session.as_deref(), Command::ConfigureBreakpoint(cfg))
            .unwrap();
        go(&c, &s);
        let hit = wait(&c, State::Paused);
        assert_eq!(hit.reason.as_deref(), Some("hardwareBreakpoint"));
        let bytes = c
            .command(
                s.session.as_deref(),
                Command::Memory {
                    address: target,
                    length: 8,
                },
            )
            .unwrap();
        let first = bytes["bytes"][0].as_u64();
        assert!(
            matches!(first, Some(0xFE | 0xEF))
                || (kind == BreakpointKind::ReadWrite && first == Some(0)),
            "read/write may observe the fixture polling zero before its first store: {bytes}"
        );
        c.command(
            s.session.as_deref(),
            Command::Breakpoint {
                action: "disable".into(),
                address: None,
                id: Some(hit.breakpoints[0].id),
            },
        )
        .unwrap();
        go(&c, &s);
        assert_eq!(wait(&c, State::Exited).exit_code, Some(42));
    }
}
#[test]
fn actual_conditional_false_hits_and_count_filter_execute_each_original_call() {
    let (c, s) = launch();
    let mut cfg = BreakpointConfig::software(export(&s, "ura_marker"));
    cfg.condition = Some("(RCX & 3) == 2 && RSP > 0x10000".into());
    cfg.hit_after = 2;
    cfg.hit_every = 2;
    c.command(s.session.as_deref(), Command::ConfigureBreakpoint(cfg))
        .unwrap();
    go(&c, &s);
    let hit = wait(&c, State::Paused);
    assert_eq!(hit.registers.as_ref().unwrap().values["rcx"], "0x2");
    assert_eq!(hit.breakpoints[0].hits, 2);
    go(&c, &s);
    assert_eq!(wait(&c, State::Exited).exit_code, Some(42));
}
#[test]
fn actual_trace_records_steps_limits_changes_and_export_identity() {
    let (c, s) = launch();
    let target = export(&s, "ura_marker");
    c.command(s.session.as_deref(), Command::RunTo { address: target })
        .unwrap();
    wait(&c, State::Paused);
    c.command(
        s.session.as_deref(),
        Command::Trace(TraceAction::Start(TraceConfig {
            mode: TraceMode::Instructions,
            max_steps: 6,
            max_events: 5,
            ..Default::default()
        })),
    )
    .unwrap();
    let traced = wait(&c, State::Paused);
    assert_eq!(traced.reason.as_deref(), Some("trace"));
    let data = c
        .command(s.session.as_deref(), Command::Trace(TraceAction::Export))
        .unwrap();
    assert_eq!(data["summary"]["steps"], 6);
    assert_eq!(data["summary"]["stopReason"], "stepLimit");
    assert!(data["summary"]["dropped"].as_u64().unwrap() > 0);
    let events = data["events"].as_array().unwrap();
    assert!(events.len() <= 5);
    assert!(events
        .iter()
        .any(|e| e["kind"] == "instruction" && e["address"].is_string()));
    for pair in events.windows(2) {
        assert!(pair[0]["sequence"].as_u64() < pair[1]["sequence"].as_u64());
    }
    assert_eq!(data["session"].as_str(), s.session.as_deref());
    kill(&c, &s);
}
#[test]
fn actual_capture_regions_compare_decode_bounds_and_unwind_step_out() {
    let (c, s) = launch();
    let target = export(&s, "ura_marker");
    c.command(s.session.as_deref(), Command::RunTo { address: target })
        .unwrap();
    let hit = wait(&c, State::Paused);
    let r = c
        .command(
            s.session.as_deref(),
            Command::Regions {
                address: target,
                limit: 2,
            },
        )
        .unwrap();
    assert!(r["regions"].as_array().unwrap()[0]["readable"]
        .as_bool()
        .unwrap());
    let first = c
        .command(
            s.session.as_deref(),
            Command::Capture(CaptureAction::Capture {
                address: target,
                length: 64,
            }),
        )
        .unwrap();
    assert_eq!(first["captured"], 64);
    assert_eq!(first["missing"], 0);
    let id = first["id"].as_u64().unwrap();
    assert!(c
        .command(
            s.session.as_deref(),
            Command::Capture(CaptureAction::Capture {
                address: target,
                length: usize::MAX
            })
        )
        .is_err());
    let compared = c
        .command(
            s.session.as_deref(),
            Command::Capture(CaptureAction::Compare { id, other: None }),
        )
        .unwrap();
    assert_eq!(compared["changedBytes"], 0);
    let decoded = c
        .command(
            s.session.as_deref(),
            Command::Capture(CaptureAction::Disassembly {
                id,
                address: target,
                count: 4,
            }),
        )
        .unwrap();
    assert!(!decoded["instructions"].as_array().unwrap().is_empty());
    let partial = c
        .command(
            s.session.as_deref(),
            Command::Capture(CaptureAction::Capture {
                address: 0,
                length: 4096,
            }),
        )
        .unwrap();
    assert_eq!(partial["captured"], 0);
    assert_eq!(partial["missing"], 4096);
    assert!(c
        .command(
            s.session.as_deref(),
            Command::Capture(CaptureAction::Capture {
                address: target,
                length: 1048577
            })
        )
        .is_err());
    let stack = c
        .command(
            s.session.as_deref(),
            Command::Stack {
                thread: None,
                limit: 4,
            },
        )
        .unwrap();
    let caller = stack["frames"][1]["instructionPointer"].as_str().unwrap();
    c.command(s.session.as_deref(), Command::StepOut).unwrap();
    let out = wait(&c, State::Paused);
    assert_eq!(out.registers.as_ref().unwrap().values["rip"], caller);
    assert!(out.breakpoints.iter().all(|p| p.owner == "user"));
    assert_ne!(hit.selected_thread, None);
    kill(&c, &s);
}
#[test]
fn owned_tf_and_false_data_watch_stop_after_exactly_one_store() {
    let (c, s) = launch();
    let store = export(&s, "ura_store");
    let data = export(&s, "ura_watch");
    c.command(s.session.as_deref(), Command::RunTo { address: store })
        .unwrap();
    wait(&c, State::Paused);
    let bytes = c
        .command(
            s.session.as_deref(),
            Command::Memory {
                address: store,
                length: 15,
            },
        )
        .unwrap();
    let raw = bytes["bytes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b.as_u64().unwrap() as u8)
        .collect::<Vec<_>>();
    let instruction =
        iced_x86::Decoder::with_ip(64, &raw, store, iced_x86::DecoderOptions::NONE).decode();
    assert_eq!(instruction.mnemonic(), iced_x86::Mnemonic::Mov);
    let mut cfg = BreakpointConfig::software(data);
    cfg.kind = BreakpointKind::Write;
    cfg.length = 8;
    cfg.condition = Some("0".into());
    c.command(s.session.as_deref(), Command::ConfigureBreakpoint(cfg))
        .unwrap();
    c.command(s.session.as_deref(), Command::Step { over: false })
        .unwrap();
    let step = wait(&c, State::Paused);
    assert_eq!(step.reason.as_deref(), Some("singleStep"));
    assert_eq!(
        step.registers.as_ref().unwrap().values["rip"],
        hex(instruction.next_ip())
    );
    assert_eq!(step.breakpoints[0].hits, 1);
    c.command(
        s.session.as_deref(),
        Command::Breakpoint {
            action: "remove".into(),
            address: None,
            id: Some(step.breakpoints[0].id),
        },
    )
    .unwrap();
    go(&c, &s);
    assert_eq!(wait(&c, State::Exited).exit_code, Some(42));
}
#[test]
fn local_pdb_identity_lookup_and_mismatch_rejection() {
    use std::os::windows::process::CommandExt;
    let (c, s) = launch();
    let base = ura_core::parse_address(&s.modules[0].base).unwrap();
    let matched = c
        .command(
            s.session.as_deref(),
            Command::Symbols(SymbolAction::Load {
                base,
                pdb: fixture::fixture().with_extension("pdb"),
            }),
        )
        .unwrap();
    assert_eq!(matched["identityMatched"], true);
    let found = c
        .command(
            s.session.as_deref(),
            Command::Symbols(SymbolAction::Lookup {
                address: export(&s, "ura_marker") + 1,
            }),
        )
        .unwrap();
    assert_eq!(found["found"], true);
    assert!(found["name"].as_str().unwrap().contains("ura_marker"));
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("other.rs");
    let output = dir.path().join("other.exe");
    std::fs::write(&source, "fn main(){std::hint::black_box(7654321);}").unwrap();
    let compiled = std::process::Command::new("rustc")
        .args(["--edition=2021", "-C", "debuginfo=2"])
        .arg(source)
        .arg("-o")
        .arg(&output)
        .creation_flags(0x08000000)
        .output()
        .unwrap();
    assert!(compiled.status.success());
    let error = c
        .command(
            s.session.as_deref(),
            Command::Symbols(SymbolAction::Load {
                base,
                pdb: output.with_extension("pdb"),
            }),
        )
        .unwrap_err();
    assert_eq!(error.code, "identity");
    assert!(c
        .command(
            s.session.as_deref(),
            Command::Symbols(SymbolAction::Lookup {
                address: export(&s, "ura_marker")
            })
        )
        .unwrap()["found"]
        .as_bool()
        .unwrap());
    kill(&c, &s);
}
#[test]
fn instruction_trace_deadline_and_user_stop_interrupt_an_actual_blocking_syscall() {
    use object::ObjectSection;
    for user_stop in [false, true] {
        let c = Controller::new();
        c.command(
            None,
            Command::Launch(LaunchConfig {
                executable: fixture::fixture(),
                expected_sha256: None,
                arguments: vec!["--blocking".into()],
                working_directory: None,
                environment: Default::default(),
                break_at_entry: true,
            }),
        )
        .unwrap();
        let s = wait(&c, State::Paused);
        let ntdll = s
            .modules
            .iter()
            .find(|m| {
                m.path
                    .as_ref()
                    .is_some_and(|p| p.to_ascii_lowercase().ends_with("ntdll.dll"))
            })
            .unwrap();
        let bytes = std::fs::read(ntdll.path.as_ref().unwrap()).unwrap();
        let file = object::File::parse(bytes.as_slice()).unwrap();
        let export = file
            .exports()
            .unwrap()
            .into_iter()
            .find(|e| e.name() == b"NtDelayExecution")
            .unwrap()
            .address();
        let code = file
            .sections()
            .find_map(|section| section.data_range(export, 64).ok().flatten())
            .unwrap();
        let mut decoder =
            iced_x86::Decoder::with_ip(64, code, export, iced_x86::DecoderOptions::NONE);
        let instruction=decoder.iter().find(|i|i.mnemonic()==iced_x86::Mnemonic::Syscall).expect("tested Windows NtDelayExecution exposes its syscall instruction in the bounded stub");
        let syscall = ura_core::parse_address(&ntdll.base).unwrap() + instruction.ip()
            - file.relative_address_base();
        c.command(s.session.as_deref(), Command::RunTo { address: syscall })
            .unwrap();
        let blocked = wait(&c, State::Paused);
        let thread = blocked.selected_thread;
        let started = Instant::now();
        c.command(
            s.session.as_deref(),
            Command::Trace(TraceAction::Start(TraceConfig {
                mode: TraceMode::Instructions,
                max_duration_ms: if user_stop { 5000 } else { 30 },
                ..Default::default()
            })),
        )
        .unwrap();
        if user_stop {
            c.command(s.session.as_deref(), Command::Trace(TraceAction::Stop))
                .unwrap();
        }
        let stopped = wait(&c, State::Paused);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "trace must interrupt the two-second wait"
        );
        assert_eq!(
            stopped.trace["stopReason"],
            if user_stop { "user" } else { "durationLimit" }
        );
        assert_eq!(stopped.trace["instructionInFlight"], false);
        let regs = c
            .command(s.session.as_deref(), Command::Registers { thread })
            .unwrap();
        let tf =
            ura_core::parse_address(regs["values"]["eflags"].as_str().unwrap()).unwrap() & 0x100;
        assert!(
            tf == 0 || stopped.trace["pendingInstructionCleanup"] == true,
            "an interrupted instruction must retain explicit cleanup ownership"
        );
        kill(&c, &s);
    }
}
#[test]
fn hardware_detach_restores_owned_slots_and_preserves_normal_target_exit() {
    use windows_sys::Win32::{Foundation::*, System::Threading::*};
    for _ in 0..8 {
        let (c, s) = launch();
        let mut cfg = BreakpointConfig::software(export(&s, "ura_watch"));
        cfg.kind = BreakpointKind::Write;
        cfg.length = 8;
        c.command(s.session.as_deref(), Command::ConfigureBreakpoint(cfg))
            .unwrap();
        go(&c, &s);
        wait(&c, State::Paused);
        unsafe {
            let process = OpenProcess(
                PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                s.pid.unwrap(),
            );
            assert!(!process.is_null());
            c.command(s.session.as_deref(), Command::Detach).unwrap();
            assert_eq!(WaitForSingleObject(process, 5000), WAIT_OBJECT_0);
            let mut code = 0;
            assert_ne!(GetExitCodeProcess(process, &mut code), 0);
            assert_eq!(code, 42, "detach events: {:#?}", c.snapshot().events);
            assert_ne!(CloseHandle(process), 0);
        }
        // Cooperative per-thread cleanup may observe the fixture's natural exit.
        assert!(matches!(
            c.snapshot().state,
            State::Detached | State::Exited
        ));
    }
}
#[test]
fn event_trace_finishes_on_actual_exit_and_retains_observed_lifecycle() {
    let (c, s) = launch();
    c.command(
        s.session.as_deref(),
        Command::Trace(TraceAction::Start(TraceConfig {
            max_duration_ms: 60000,
            ..Default::default()
        })),
    )
    .unwrap();
    go(&c, &s);
    let exit = wait(&c, State::Exited);
    assert_eq!(exit.trace["active"], false);
    assert_eq!(exit.trace["stopReason"], "processExited");
    let trace = c
        .command(s.session.as_deref(), Command::Trace(TraceAction::Export))
        .unwrap();
    assert!(trace["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["kind"] == "processExited"));
}
#[test]
fn repeated_trace_pause_detach_races_preserve_owned_target_exit() {
    use windows_sys::Win32::{Foundation::*, System::Threading::*};
    for _ in 0..8 {
        let (c, s) = launch();
        unsafe {
            let process = OpenProcess(
                PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                s.pid.unwrap(),
            );
            assert!(!process.is_null());
            c.command(
                s.session.as_deref(),
                Command::Trace(TraceAction::Start(TraceConfig {
                    mode: TraceMode::Instructions,
                    max_steps: 100000,
                    max_duration_ms: 5000,
                    ..Default::default()
                })),
            )
            .unwrap();
            c.command(s.session.as_deref(), Command::Pause).unwrap();
            wait(&c, State::Paused);
            c.command(s.session.as_deref(), Command::Detach).unwrap();
            assert_eq!(WaitForSingleObject(process, 5000), WAIT_OBJECT_0);
            let mut code = 0;
            assert_ne!(GetExitCodeProcess(process, &mut code), 0);
            assert_eq!(code, 42);
            assert_ne!(CloseHandle(process), 0);
        }
    }
}

#[test]
fn another_thread_software_hit_during_tf_serializes_and_detaches_cleanly() {
    use windows_sys::Win32::{Foundation::*, System::Threading::*};
    let (c, s) = launch_args(&["--step-race"]);
    c.command(
        s.session.as_deref(),
        Command::RunTo {
            address: export(&s, "ura_step_wait"),
        },
    )
    .unwrap();
    wait(&c, State::Paused);
    c.command(
        s.session.as_deref(),
        Command::Breakpoint {
            action: "set".into(),
            address: Some(export(&s, "ura_marker")),
            id: None,
        },
    )
    .unwrap();
    c.command(
        s.session.as_deref(),
        Command::Trace(TraceAction::Start(TraceConfig {
            mode: TraceMode::Instructions,
            max_duration_ms: 5000,
            max_steps: 10000,
            ..Default::default()
        })),
    )
    .unwrap();
    let hit = wait(&c, State::Paused);
    assert_eq!(hit.reason.as_deref(), Some("breakpoint"));
    c.command(
        s.session.as_deref(),
        Command::Continue {
            pass_exception: true,
        },
    )
    .unwrap();
    let completed = wait(&c, State::Paused);
    assert_eq!(completed.reason.as_deref(), Some("singleStep"));
    unsafe {
        let process = OpenProcess(
            PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            s.pid.unwrap(),
        );
        assert!(!process.is_null());
        c.command(s.session.as_deref(), Command::Detach).unwrap();
        assert_eq!(WaitForSingleObject(process, 5000), WAIT_OBJECT_0);
        let mut code = 0;
        assert_ne!(GetExitCodeProcess(process, &mut code), 0);
        assert_ne!(CloseHandle(process), 0);
        assert_eq!(code, 42, "events: {:#?}", c.snapshot().events);
    }
}
