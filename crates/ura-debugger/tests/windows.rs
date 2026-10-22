#![cfg(all(windows, target_arch = "x86_64"))]
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};
use ura_debugger::*;
#[path = "../../../tests/support/debug_fixture.rs"]
mod debug_fixture;
fn fixture() -> PathBuf {
    debug_fixture::fixture()
}

fn wait(controller: &Controller, condition: impl Fn(&Snapshot) -> bool) -> Snapshot {
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        let view = controller.snapshot();
        if condition(&view) {
            return view;
        }
        assert!(Instant::now() < deadline, "debugger timeout: {view:#?}");
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn launch(controller: &Controller, args: Vec<String>) -> Snapshot {
    controller
        .command(
            None,
            Command::Launch(LaunchConfig {
                executable: fixture(),
                expected_sha256: None,
                arguments: args,
                working_directory: None,
                environment: Default::default(),
                break_at_entry: true,
            }),
        )
        .unwrap();
    wait(controller, |s| s.state == State::Paused)
}
#[test]
fn real_launch_breakpoint_repeat_step_register_memory_stack_exit() {
    use object::Object;
    let controller = Controller::new();
    let view = launch(&controller, vec![]);
    assert_eq!(view.reason.as_deref(), Some("breakpoint"));
    let session = view.session.as_deref();
    assert!(view.registers.is_some());
    assert!(!view.modules.is_empty());
    let image = std::fs::read(fixture()).unwrap();
    let file = object::File::parse(image.as_slice()).unwrap();
    let export = file
        .exports()
        .unwrap()
        .into_iter()
        .find(|e| e.name() == b"ura_marker")
        .unwrap()
        .address();
    let base = ura_core::parse_address(&view.modules[0].base).unwrap();
    let address = base + export - file.relative_address_base();
    controller
        .command(
            session,
            Command::Breakpoint {
                action: "set".into(),
                address: Some(address),
                id: None,
            },
        )
        .unwrap();
    controller
        .command(
            session,
            Command::Continue {
                pass_exception: true,
            },
        )
        .unwrap();
    let hit = wait(&controller, |s| s.state == State::Paused);
    assert_eq!(hit.registers.as_ref().unwrap().values["rip"], hex(address));
    assert_eq!(hit.breakpoints[0].hits, 1);
    assert!(
        hit.threads.len() >= 2,
        "owned worker must remain live during breakpoint displacement"
    );
    let other = hit
        .threads
        .iter()
        .find(|t| Some(t.id) != hit.selected_thread)
        .unwrap()
        .id;
    let other_context = controller
        .command(
            session,
            Command::Registers {
                thread: Some(other),
            },
        )
        .unwrap();
    assert_eq!(other_context["thread"], other);
    controller
        .command(
            session,
            Command::Registers {
                thread: hit.selected_thread,
            },
        )
        .unwrap();
    let memory = controller
        .command(
            session,
            Command::Memory {
                address,
                length: 16,
            },
        )
        .unwrap();
    assert_eq!(memory["read"], 16);
    assert_eq!(
        memory["bytes"][0].as_u64().unwrap(),
        hit.breakpoints[0].original_byte as u64
    );
    let stack = controller
        .command(
            session,
            Command::Stack {
                thread: None,
                limit: 16,
            },
        )
        .unwrap();
    assert!(stack["frames"].as_array().unwrap().len() >= 2, "{stack}");
    controller
        .command(session, Command::Step { over: false })
        .unwrap();
    let stepped = wait(&controller, |s| s.state == State::Paused);
    assert_eq!(stepped.reason.as_deref(), Some("singleStep"));
    assert!(stepped.breakpoints[0].armed);
    controller
        .command(
            session,
            Command::Continue {
                pass_exception: true,
            },
        )
        .unwrap();
    let hit2 = wait(&controller, |s| s.state == State::Paused);
    assert_eq!(hit2.breakpoints[0].hits, 2);
    controller
        .command(
            session,
            Command::Breakpoint {
                action: "remove".into(),
                address: None,
                id: Some(hit2.breakpoints[0].id),
            },
        )
        .unwrap();
    controller
        .command(
            session,
            Command::Breakpoint {
                action: "set".into(),
                address: Some(address),
                id: None,
            },
        )
        .unwrap();
    assert!(
        !controller.snapshot().breakpoints[0].armed,
        "restored current-IP breakpoint waits for its displaced instruction"
    );
    controller
        .command(
            session,
            Command::Continue {
                pass_exception: true,
            },
        )
        .unwrap();
    let third = wait(&controller, |s| s.state == State::Paused);
    assert_eq!(third.registers.as_ref().unwrap().values["rcx"], "0x3");
    controller
        .command(
            session,
            Command::Breakpoint {
                action: "remove".into(),
                address: None,
                id: Some(third.breakpoints[0].id),
            },
        )
        .unwrap();
    controller
        .command(
            session,
            Command::Continue {
                pass_exception: true,
            },
        )
        .unwrap();
    let exited = wait(&controller, |s| s.state == State::Exited);
    assert_eq!(exited.exit_code, Some(42));
    for kind in [
        "threadCreated",
        "threadExited",
        "moduleLoaded",
        "moduleUnloaded",
        "processExited",
    ] {
        assert!(
            exited.events.iter().any(|e| e.kind == kind),
            "missing {kind}"
        );
    }
    assert!(exited.registers.is_none());
    assert!(controller
        .command(Some("debug-stale"), Command::Pause)
        .is_err());
}
#[test]
fn real_attach_detach_restores_breakpoint_and_preserves_target() {
    use std::os::windows::process::CommandExt;
    let mut child = std::process::Command::new(fixture())
        .arg("--attach")
        .creation_flags(0x08000000)
        .spawn()
        .unwrap();
    let controller = Controller::new();
    controller
        .command(
            None,
            Command::Attach {
                pid: child.id(),
                executable: fixture(),
                expected_sha256: None,
            },
        )
        .unwrap();
    let view = wait(&controller, |s| s.state == State::Paused);
    assert!(view.attached);
    let session = view.session.as_deref();
    let entry =
        ura_core::parse_address(view.registers.as_ref().unwrap().values.get("rip").unwrap())
            .unwrap();
    // Use a known file function, not the system's own INT3 instruction.
    use object::Object;
    let bytes = std::fs::read(fixture()).unwrap();
    let file = object::File::parse(bytes.as_slice()).unwrap();
    let marker = file
        .exports()
        .unwrap()
        .into_iter()
        .find(|e| e.name() == b"ura_marker")
        .unwrap()
        .address();
    let address = ura_core::parse_address(&view.modules[0].base).unwrap() + marker
        - file.relative_address_base();
    assert_ne!(entry, address);
    controller
        .command(
            session,
            Command::Breakpoint {
                action: "set".into(),
                address: Some(address),
                id: None,
            },
        )
        .unwrap();
    controller.command(session, Command::Detach).unwrap();
    assert_eq!(controller.snapshot().state, State::Detached);
    let deadline = Instant::now() + Duration::from_secs(7);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert_eq!(status.code(), Some(42));
            break;
        }
        assert!(
            Instant::now() < deadline,
            "detached owned fixture did not exit"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
#[test]
fn real_step_over_direct_call_reaches_exact_return_address() {
    use object::Object;
    let controller = Controller::new();
    let view = launch(&controller, vec![]);
    let session = view.session.as_deref();
    let image = std::fs::read(fixture()).unwrap();
    let file = object::File::parse(image.as_slice()).unwrap();
    let caller = file
        .exports()
        .unwrap()
        .into_iter()
        .find(|e| e.name() == b"ura_nested")
        .unwrap()
        .address();
    let address = ura_core::parse_address(&view.modules[0].base).unwrap() + caller
        - file.relative_address_base();
    let memory = controller
        .command(
            session,
            Command::Memory {
                address,
                length: 128,
            },
        )
        .unwrap();
    let bytes = memory["bytes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect::<Vec<_>>();
    let mut decoder =
        iced_x86::Decoder::with_ip(64, &bytes, address, iced_x86::DecoderOptions::NONE);
    let call = decoder
        .iter()
        .find(|i| i.flow_control() == iced_x86::FlowControl::Call)
        .unwrap();
    controller
        .command(
            session,
            Command::Breakpoint {
                action: "set".into(),
                address: Some(call.ip()),
                id: None,
            },
        )
        .unwrap();
    controller
        .command(
            session,
            Command::Continue {
                pass_exception: true,
            },
        )
        .unwrap();
    let hit = wait(&controller, |s| s.state == State::Paused);
    assert_eq!(
        hit.registers.as_ref().unwrap().values["rip"],
        hex(call.ip())
    );
    let sp = hit.registers.as_ref().unwrap().values["rsp"].clone();
    controller
        .command(session, Command::Step { over: true })
        .unwrap();
    let stepped = wait(&controller, |s| s.state == State::Paused);
    assert_eq!(
        stepped.registers.as_ref().unwrap().values["rip"],
        hex(call.next_ip())
    );
    assert_eq!(stepped.registers.as_ref().unwrap().values["rsp"], sp);
    assert!(stepped.breakpoints.iter().all(|p| p.owner != "stepOver"));
    controller.command(session, Command::Terminate).unwrap();
    wait(&controller, |s| s.state == State::Exited);
}
#[test]
fn real_pause_memory_boundaries_and_drop_cleanup() {
    let controller = Controller::new();
    let view = launch(&controller, vec!["--attach".into()]);
    let session = view.session.as_deref();
    assert!(controller
        .command(
            session,
            Command::Memory {
                address: 0,
                length: 0
            }
        )
        .is_err());
    let unreadable = controller
        .command(
            session,
            Command::Memory {
                address: 0,
                length: 16,
            },
        )
        .unwrap();
    assert_eq!(unreadable["read"], 0);
    assert_eq!(unreadable["partial"], true);
    controller
        .command(
            session,
            Command::Continue {
                pass_exception: true,
            },
        )
        .unwrap();
    assert!(controller
        .command(session, Command::Step { over: false })
        .is_err());
    controller.command(session, Command::Pause).unwrap();
    let paused = wait(&controller, |s| s.state == State::Paused);
    assert_eq!(paused.reason.as_deref(), Some("pause"));
    controller.command(session, Command::Terminate).unwrap();
    wait(&controller, |s| s.state == State::Exited);
}
#[test]
fn backend_rejects_unapproved_locked_hash_before_execution() {
    let controller = Controller::new();
    let result = controller.command(
        None,
        Command::Launch(LaunchConfig {
            executable: fixture(),
            expected_sha256: Some("0".repeat(64)),
            arguments: vec![],
            working_directory: None,
            environment: Default::default(),
            break_at_entry: true,
        }),
    );
    assert!(result.is_err());
    assert!(controller.snapshot().pid.is_none());
}

#[test]
fn application_breakpoint_is_not_swallowed_as_debugger_pause() {
    let controller = Controller::new();
    let view = launch(&controller, vec!["--application-break".into()]);
    let session = view.session.as_deref();
    controller
        .command(
            session,
            Command::Continue {
                pass_exception: true,
            },
        )
        .unwrap();
    let exception = wait(&controller, |s| s.state == State::Paused);
    assert_eq!(exception.reason.as_deref(), Some("applicationException"));
    assert_eq!(exception.first_chance, Some(true));
    controller
        .command(
            session,
            Command::Continue {
                pass_exception: true,
            },
        )
        .unwrap();
    let second = wait(&controller, |s| {
        s.state == State::Paused || s.state == State::Exited
    });
    if second.state == State::Paused {
        assert_eq!(second.first_chance, Some(false));
        controller
            .command(
                session,
                Command::Continue {
                    pass_exception: true,
                },
            )
            .unwrap();
    }
    let exited = wait(&controller, |s| s.state == State::Exited);
    assert_ne!(exited.exit_code, Some(42));
}
