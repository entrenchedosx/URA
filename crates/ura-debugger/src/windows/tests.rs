use super::*;
#[path = "../../../../tests/support/debug_fixture.rs"]
mod debug_fixture;
fn config() -> LaunchConfig {
    LaunchConfig {
        executable: debug_fixture::fixture(),
        expected_sha256: None,
        arguments: vec![],
        working_directory: None,
        environment: Default::default(),
        break_at_entry: true,
    }
}
fn paused() -> WindowsBackend {
    let snapshot = Arc::new(Mutex::new(Snapshot {
        schema_version: 1,
        ..Default::default()
    }));
    let mut backend = WindowsBackend::new(snapshot);
    backend
        .command(
            None,
            Command::Launch(config()),
            &std::sync::atomic::AtomicBool::new(false),
        )
        .unwrap();
    let deadline = Instant::now() + std::time::Duration::from_secs(8);
    while backend.view.state != State::Paused {
        backend.poll();
        assert!(Instant::now() < deadline, "{:?}", backend.view);
    }
    backend
}
#[test]
fn failed_continuation_rolls_back_real_context_and_owned_suspensions() {
    let mut backend = paused();
    let tid = backend.view.selected_thread.unwrap();
    let before = context(backend.threads[&tid].0).unwrap();
    backend.fail_next_continue = true;
    assert!(backend.resume(Some(false), true).is_err());
    assert!(backend.pending.is_some());
    assert!(backend.step.is_none());
    assert!(backend.points.is_empty());
    let after = context(backend.threads[&tid].0).unwrap();
    assert_eq!(before.0.Rip, after.0.Rip);
    assert_eq!(before.0.EFlags, after.0.EFlags);
    backend.resume(Some(false), true).unwrap();
    let deadline = Instant::now() + std::time::Duration::from_secs(5);
    while backend.view.state != State::Paused {
        backend.poll();
        assert!(Instant::now() < deadline);
    }
    assert_eq!(backend.view.reason.as_deref(), Some("singleStep"));
}
#[test]
fn interrupted_step_validation_preserves_preexisting_cleanup_ownership() {
    let mut backend = paused();
    let tid = backend.view.selected_thread.unwrap();
    let h = backend.threads[&tid].0;
    let mut c = context(h).unwrap();
    c.0.EFlags |= 0x100;
    set_context(h, &c).unwrap();
    // Model an interrupted owned step while a real Windows event holds all threads.
    backend.step = Some(SingleStep {
        thread: tid,
        rearm: None,
        stop: true,
        frozen: vec![],
    });
    assert!(backend.resume(None, true).is_err());
    assert!(backend.step.is_some());
    assert_ne!(context(h).unwrap().0.EFlags & 0x100, 0);
    backend.abort_step().unwrap();
    assert_eq!(context(h).unwrap().0.EFlags & 0x100, 0);
}
#[test]
fn cancelled_launch_does_not_create_a_process_and_events_are_bounded() {
    let snapshot = Arc::new(Mutex::new(Snapshot {
        schema_version: 1,
        ..Default::default()
    }));
    let mut backend = WindowsBackend::new(snapshot);
    assert!(backend
        .command(
            None,
            Command::Launch(config()),
            &std::sync::atomic::AtomicBool::new(true)
        )
        .is_err());
    assert!(backend.view.pid.is_none());
    for _ in 0..300 {
        backend.event(0, "test", "bounded event");
    }
    assert_eq!(backend.view.events.len(), MAX_EVENTS);
    assert!(backend.view.events_dropped > 0);
}
#[test]
fn uncertain_software_write_retains_ownership_until_byte_and_protection_restored() {
    for failure in [1, 2] {
        let mut backend = paused();
        let tid = backend.view.selected_thread.unwrap();
        let ip = context(backend.threads[&tid].0).unwrap().0.Rip;
        let before = memory(backend.process().unwrap(), ip, 1).unwrap();
        let process = duplicate(backend.process().unwrap()).unwrap();
        unsafe {
            check(
                DebugBreakProcess(process.0),
                "owned pending pause before fault",
            )
            .unwrap();
        }
        backend.pause_requested = true;
        os::BYTE_ROLLBACK_FAILURE.with(|f| f.set(failure));
        let error = backend.add_point(ip, None, "user").unwrap_err();
        assert_eq!(error.code, "critical");
        assert!(backend.points[&ip].uncertain);
        assert_eq!(
            backend.points[&ip].protection as u64,
            before["region"]["protection"].as_u64().unwrap()
        );
        assert!(backend.resume(None, true).is_err());
        backend.detach_paused().unwrap();
        unsafe {
            assert_eq!(WaitForSingleObject(process.0, 4000), WAIT_OBJECT_0);
            let mut code = 0;
            assert_ne!(GetExitCodeProcess(process.0, &mut code), 0);
            assert_eq!(code, 42);
        }
    }
}

#[test]
fn debug_event_identity_failure_cannot_be_resumed_or_inspected() {
    let snapshot = Arc::new(Mutex::new(Snapshot {
        schema_version: 1,
        ..Default::default()
    }));
    let mut backend = WindowsBackend::new(snapshot);
    backend
        .command(
            None,
            Command::Launch(config()),
            &std::sync::atomic::AtomicBool::new(false),
        )
        .unwrap();
    // Fault injection at the event-validation boundary, while real creation is stopped.
    backend.image.as_mut().unwrap().hash = "0".repeat(64);
    let deadline = Instant::now() + std::time::Duration::from_secs(5);
    while !backend.authorization_failed {
        backend.poll();
        assert!(Instant::now() < deadline);
    }
    let session = backend.view.session.clone();
    for command in [
        Command::Continue {
            pass_exception: true,
        },
        Command::Step { over: false },
        Command::Memory {
            address: 0,
            length: 1,
        },
        Command::Breakpoint {
            action: "set".into(),
            address: Some(0),
            id: None,
        },
    ] {
        assert!(backend
            .command(
                session.as_deref(),
                command,
                &std::sync::atomic::AtomicBool::new(false)
            )
            .is_err());
    }
    while backend.view.state != State::Exited {
        backend.poll();
        assert!(Instant::now() < deadline);
    }
}
#[test]
fn detach_drains_inflight_pause_before_leaving_owned_target_running() {
    let mut backend = paused();
    let process = duplicate(backend.process().unwrap()).unwrap();
    unsafe {
        check(
            DebugBreakProcess(backend.process().unwrap()),
            "test requested break",
        )
        .unwrap();
    }
    backend.pause_requested = true;
    backend.detach_paused().unwrap();
    assert_eq!(backend.view.state, State::Detached);
    unsafe {
        assert_eq!(WaitForSingleObject(process.0, 5000), WAIT_OBJECT_0);
        let mut code = 0;
        check(
            GetExitCodeProcess(process.0, &mut code),
            "fixture exit code",
        )
        .unwrap();
        assert_eq!(
            code, 42,
            "no delayed unhandled debugger INT3 may remain after detach"
        );
    }
}

#[test]
fn cleanup_failure_before_exception_classification_preserves_application_disposition() {
    let snapshot = Arc::new(Mutex::new(Snapshot {
        schema_version: 1,
        ..Default::default()
    }));
    let mut backend = WindowsBackend::new(snapshot);
    let mut launch = config();
    launch.arguments = vec!["--application-break".into()];
    backend
        .command(
            None,
            Command::Launch(launch),
            &std::sync::atomic::AtomicBool::new(false),
        )
        .unwrap();
    let deadline = Instant::now() + std::time::Duration::from_secs(8);
    loop {
        backend.poll();
        assert!(Instant::now() < deadline);
        if backend.view.state == State::Paused {
            if backend.view.reason.as_deref() == Some("applicationException") {
                break;
            }
            backend.resume(None, true).unwrap();
        }
    }
    let process = duplicate(backend.process().unwrap()).unwrap();
    let event = backend.pending.as_ref().unwrap().0;
    let tid = event.dwThreadId;
    let mut cfg = BreakpointConfig::software(0x1000);
    cfg.kind = BreakpointKind::HardwareExecute;
    cfg.thread = Some(tid);
    backend.configure_point(cfg).unwrap();
    let id = *backend.hardware.keys().next().unwrap();
    let slot = backend.hardware[&id].view.slots[&tid];
    let before = context(backend.threads[&tid].0).unwrap();
    let mut changed = context(backend.threads[&tid].0).unwrap();
    match slot {
        0 => changed.0.Dr0 += 1,
        1 => changed.0.Dr1 += 1,
        2 => changed.0.Dr2 += 1,
        _ => changed.0.Dr3 += 1,
    }
    set_context(backend.threads[&tid].0, &changed).unwrap();
    backend.hardware.get_mut(&id).unwrap().view.enabled = false;
    // Re-enter the boundary with the actual outstanding application exception;
    // slot restoration fails before its normal classification can run.
    assert!(backend.on_event(event).is_err());
    assert_eq!(
        backend.pending.as_ref().unwrap().1,
        DBG_EXCEPTION_NOT_HANDLED
    );
    set_context(backend.threads[&tid].0, &before).unwrap();
    backend.detach_paused().unwrap();
    unsafe {
        assert_eq!(WaitForSingleObject(process.0, 5000), WAIT_OBJECT_0);
        let mut code = 0;
        check(
            GetExitCodeProcess(process.0, &mut code),
            "application exception exit",
        )
        .unwrap();
        assert_eq!(code, EXCEPTION_BREAKPOINT as u32);
    }
}
