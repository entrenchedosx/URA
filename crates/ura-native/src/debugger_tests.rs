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
    let address = debugger.snapshot.registers.as_ref().unwrap().values["rip"].clone();
    debugger.request(
        "capture",
        json!({"operation":"snapshot","action":"capture","address":address,"length":32}),
        &ctx,
    );
    wait(&mut debugger, &ctx, State::Paused);
    assert_eq!(debugger.advanced["capture"]["captured"], 32);
    debugger.request(
        "trace",
        json!({"operation":"trace","action":"start","config":{"mode":"instructions","maxSteps":3}}),
        &ctx,
    );
    wait(&mut debugger, &ctx, State::Paused);
    assert_eq!(debugger.snapshot.trace["steps"], 3);
    debugger.request(
        "trace",
        json!({"operation":"trace","action":"read","limit":128}),
        &ctx,
    );
    wait(&mut debugger, &ctx, State::Paused);
    assert!(
        debugger.advanced["trace"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["kind"] == "instruction")
    );
    debugger.request("control", json!({"operation":"terminate"}), &ctx);
    wait(&mut debugger, &ctx, State::Exited);
    assert!(debugger.inspection.is_null());
}
#[test]
fn actual_trace_view_headless_rendering_benchmark() {
    let ctx = egui::Context::default();
    let mut debugger = DebugUi {
        path: debug_fixture::fixture().display().to_string(),
        ..Default::default()
    };
    debugger.start(false, &ctx);
    wait(&mut debugger, &ctx, State::Paused);
    debugger.request("trace",json!({"operation":"trace","action":"start","config":{"mode":"instructions","maxSteps":128,"maxEvents":4096,"maxBytes":1048576}}),&ctx);
    wait(&mut debugger, &ctx, State::Paused);
    debugger.request(
        "trace",
        json!({"operation":"trace","action":"read","limit":512}),
        &ctx,
    );
    wait(&mut debugger, &ctx, State::Paused);
    let count = debugger.advanced["trace"]["events"]
        .as_array()
        .unwrap()
        .len();
    assert!(count >= 128);
    let mut workspace = Workspace::new(ctx.clone(), crate::app::Settings::default(), vec![]);
    workspace.debugger = debugger;
    let mut measurements = Vec::new();
    for theme in [crate::design::Theme::Classic, crate::design::Theme::Dark] {
        workspace.settings.theme = theme;
        crate::design::apply(&ctx, &workspace.settings);
        for scale in [1.0, 1.5] {
            ctx.set_pixels_per_point(scale);
            let mut samples = Vec::new();
            for _ in 0..3 {
                let started = std::time::Instant::now();
                let mut output = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(1280.0 / scale, 720.0 / scale),
                        )),
                        ..Default::default()
                    },
                    |ui| workspace.trace_panel(ui),
                );
                assert!(!output.shapes.is_empty());
                assert!(output.shapes.len() < 3000);
                output.textures_delta.clear();
                ctx.tessellate(output.shapes, scale);
                samples.push(started.elapsed().as_secs_f64() * 1000.0);
            }
            measurements.push(json!({"theme":format!("{theme:?}"),"simulatedScale":scale,"frameBuildAndTessellationMs":samples}));
        }
    }
    println!(
        "trace_view_headless {}",
        json!({"actualOwnedTraceEvents":count,"measurements":measurements,"liveInteraction":false,"realOsDpi":false,"gpuTiming":false})
    );
    workspace
        .debugger
        .request("control", json!({"operation":"terminate"}), &ctx);
    wait(&mut workspace.debugger, &ctx, State::Exited);
}
