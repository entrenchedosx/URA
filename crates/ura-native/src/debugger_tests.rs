use super::*;
#[path = "../../../tests/support/debug_fixture.rs"]
mod debug_fixture;
fn wait(ui: &mut DebugUi, ctx: &egui::Context, state: State) {
    let deadline = std::time::Instant::now() + Duration::from_secs(12);
    loop {
        ui.poll(ctx);
        if ui.snapshot.state == state && !ui.busy {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{:?} {:?}",
            ui.snapshot,
            ui.error
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
#[test]
fn native_debug_worker_captures_actual_process_state_and_renders_controls_headlessly() {
    let ctx = egui::Context::default();
    let mut debugger = DebugUi {
        path: debug_fixture::fixture().display().to_string(),
        ..Default::default()
    };
    debugger.start(false, &ctx);
    wait(&mut debugger, &ctx, State::Paused);
    assert!(debugger.error.is_none(), "{:?}", debugger.error);
    assert!(debugger.snapshot.registers.is_some());
    assert!(
        debugger.inspection["runtime"]["instructions"]
            .as_array()
            .unwrap()
            .len()
            > 1
    );
    assert!(
        !debugger.inspection["stack"]["frames"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(debugger.inspection["memory"]["read"].as_u64().unwrap() > 0);
    let mut output = ctx.run_ui(egui::RawInput::default(), |ui| debugger.controls(ui));
    output.textures_delta.clear();
    assert!(!output.shapes.is_empty());
    debugger.request("control", json!({"operation":"step"}), &ctx);
    wait(&mut debugger, &ctx, State::Paused);
    assert_eq!(debugger.snapshot.reason.as_deref(), Some("singleStep"));
    debugger.request("control", json!({"operation":"terminate"}), &ctx);
    wait(&mut debugger, &ctx, State::Exited);
    assert!(debugger.inspection.is_null());
}
