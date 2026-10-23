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

#[test]
fn targeted_hardware_point_retires_after_real_fixture_thread_exit() {
    let shared = Arc::new(Mutex::new(Snapshot {
        schema_version: 1,
        ..Default::default()
    }));
    let mut backend = WindowsBackend::new(shared);
    let mut launch = config();
    launch.arguments = vec!["--thread-exit".into()];
    backend
        .command(
            None,
            Command::Launch(launch),
            &std::sync::atomic::AtomicBool::new(false),
        )
        .unwrap();
    let deadline = Instant::now() + std::time::Duration::from_secs(10);
    while backend.view.state != State::Paused {
        backend.poll();
        assert!(Instant::now() < deadline);
    }
    let binary = ura_core::analyze_path(&debug_fixture::fixture()).unwrap();
    let rva = binary
        .analysis()
        .exports
        .iter()
        .find(|s| s.name == "ura_marker")
        .unwrap()
        .address
        - binary.analysis().image_base;
    let base = ura_core::parse_address(
        &backend
            .view
            .modules
            .iter()
            .find(|m| {
                m.path
                    .as_ref()
                    .is_some_and(|p| p.to_lowercase().ends_with(".exe"))
            })
            .unwrap()
            .base,
    )
    .unwrap();
    let marker = base + rva;
    backend
        .configure_point(BreakpointConfig::software(marker))
        .unwrap();
    backend.resume(None, true).unwrap();
    while backend.view.state != State::Paused {
        backend.poll();
        assert!(Instant::now() < deadline);
    }
    let worker = backend.view.selected_thread.unwrap();
    let mut cfg = BreakpointConfig::software(marker);
    cfg.kind = BreakpointKind::Write;
    cfg.thread = Some(worker);
    // The fixture never writes its RX code. This isolates thread-exit cleanup.
    cfg.address = marker;
    backend.configure_point(cfg).unwrap();
    let id = *backend.hardware.keys().next().unwrap();
    backend.resume(None, true).unwrap();
    while backend.view.state != State::Paused {
        backend.poll();
        assert!(Instant::now() < deadline);
    }
    // The owning thread exits before the next main-thread software marker.
    assert_ne!(backend.view.selected_thread, Some(worker));
    assert!(!backend.hardware[&id].view.enabled);
    assert!(backend.hardware[&id].view.threads.is_empty());
    backend.hardware_ready().unwrap();
}

#[test]
fn failed_event_context_update_does_not_discard_restored_parked_step() {
    let mut backend = paused();
    let tid = backend.view.selected_thread.unwrap();
    let before = context(backend.threads[&tid].0).unwrap();
    // A real event-thread update fails while another owner's execution intent
    // is parked. The parked record is synthetic; it owns no OS suspend or TF.
    let parked_tid = tid.wrapping_add(0x10000);
    backend.parked_step = Some(SingleStep {
        thread: parked_tid,
        rearm: None,
        stop: true,
        frozen: vec![],
    });
    os::FAIL_CONTEXT_ONCE.with(|f| f.set(true));
    assert!(backend.resume(Some(false), true).is_err());
    let restored = backend
        .step
        .as_ref()
        .expect("parked owner must survive rollback");
    assert_eq!(restored.thread, parked_tid);
    assert!(restored.stop);
    assert!(backend.parked_step.is_none());
    assert!(backend.pending.is_some());
    let after = context(backend.threads[&tid].0).unwrap();
    assert_eq!(before.0.EFlags, after.0.EFlags);
    assert_eq!(before.0.Rip, after.0.Rip);
    backend.step = None; // Dispose only the synthetic intent, which owns no OS resource.
}

#[test]
fn new_step_peer_has_zero_owned_suspends_for_tf_and_exactly_one_for_displacement() {
    let mut backend = paused();
    let tid = backend.view.selected_thread.unwrap();
    let h = backend.threads[&tid].0;
    let ip = context(h).unwrap().0.Rip;
    // Exercise the event policy with a real stopped owned process/thread.
    // The other step owner is a synthetic intent with no TF or OS resources.
    let owner = tid.wrapping_add(0x10000);
    backend.step = Some(SingleStep {
        thread: owner,
        rearm: None,
        stop: true,
        frozen: vec![],
    });
    backend.freeze_new_step_peer(tid, h, false).unwrap();
    assert!(backend.step.as_ref().unwrap().frozen.is_empty());
    unsafe {
        assert_eq!(SuspendThread(h), 0);
        assert_eq!(ResumeThread(h), 1);
    }
    backend.step.as_mut().unwrap().rearm = Some(ip);
    backend.freeze_new_step_peer(tid, h, false).unwrap();
    backend.freeze_new_step_peer(tid, h, false).unwrap();
    assert_eq!(backend.step.as_ref().unwrap().frozen, vec![tid]);
    unsafe {
        assert_eq!(SuspendThread(h), 1);
        assert_eq!(ResumeThread(h), 2);
    }
    backend.release_step().unwrap();
    assert!(backend.step.is_none());
    unsafe {
        assert_eq!(SuspendThread(h), 0);
        assert_eq!(ResumeThread(h), 1);
    }
}
