//! Opt-in verification of the actual renderer. Disabled in normal operation.
use crate::app::{Action, NativeApp, Panel, default_dock};
use crate::worker::Event;
use eframe::egui;
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

/// Frame sampling is enabled only for the existing benchmark environment.
/// It never requests a repaint, so idle measurements retain normal scheduling.
pub struct IdleMetrics {
    output: PathBuf,
    started: Instant,
    frames: Vec<serde_json::Value>,
}
impl IdleMetrics {
    pub fn from_env() -> Option<Self> {
        Some(Self {
            output: PathBuf::from(std::env::var_os("URA_BENCHMARK_OUTPUT")?)
                .join("idle-frames.json"),
            started: Instant::now(),
            frames: vec![],
        })
    }
    pub fn record(&mut self, ctx: &egui::Context, cpu: Option<f32>) {
        if self.frames.len() < 20_000 {
            self.frames.push(serde_json::json!({"elapsed_ms":self.started.elapsed().as_secs_f64()*1000.0,"cpu_ms":cpu.map(|v|v*1000.0),"causes":format!("{:?}",ctx.repaint_causes())}));
        }
    }
}
impl Drop for IdleMetrics {
    fn drop(&mut self) {
        if let Ok(data) = serde_json::to_vec_pretty(&self.frames) {
            let _ = std::fs::write(&self.output, data);
        }
    }
}

pub struct DisplayCheck {
    output: PathBuf,
    started: Instant,
    stage: usize,
    phase: u8,
    changed: Instant,
    frames: Vec<serde_json::Value>,
    navigation: Vec<f64>,
    first_ready: Option<f64>,
    dark: bool,
}
const SIZES: [(f32, f32, f32); 4] = [
    (1280.0, 720.0, 1.0),
    (1440.0, 900.0, 1.0),
    (1920.0, 1080.0, 1.0),
    (1920.0, 1080.0, 1.5),
];
const PANELS: [Panel; 7] = [
    Panel::Disassembly,
    Panel::Graph,
    Panel::Hex,
    Panel::Strings,
    Panel::Functions,
    Panel::Overview,
    Panel::Xrefs,
];
impl DisplayCheck {
    pub fn from_env(started: Instant) -> Option<Self> {
        let output = std::env::var_os("URA_DISPLAY_CHECK").map(PathBuf::from)?;
        Some(Self {
            output,
            started,
            stage: 0,
            phase: 0,
            changed: Instant::now(),
            frames: vec![],
            navigation: vec![],
            first_ready: None,
            dark: std::env::var("URA_DISPLAY_THEME").is_ok_and(|v| v == "dark"),
        })
    }
    pub fn update(&mut self, app: &mut NativeApp, ctx: &egui::Context, cpu_seconds: Option<f32>) {
        app.workspace.settings.theme = if self.dark {
            crate::design::Theme::Dark
        } else {
            crate::design::Theme::Classic
        };
        // NativeOptions directs verification persistence to a separate file.
        ctx.request_repaint_after(Duration::from_millis(16));
        for event in ctx.input(|i| i.raw.events.clone()) {
            if let egui::Event::Screenshot {
                image, user_data, ..
            } = event
                && let Some(name) = user_data
                    .data
                    .as_ref()
                    .and_then(|v| v.downcast_ref::<String>())
            {
                let path = self.output.join(name);
                app.workspace
                    .worker
                    .submit(app.workspace.generation, move || {
                        std::fs::create_dir_all(path.parent().unwrap())
                            .map_err(|e| e.to_string())?;
                        let rgba: Vec<_> = image.pixels.iter().flat_map(|c| c.to_array()).collect();
                        image::save_buffer(
                            &path,
                            &rgba,
                            image.width() as u32,
                            image.height() as u32,
                            image::ColorType::Rgba8,
                        )
                        .map_err(|e| e.to_string())?;
                        Ok(Event::Message(format!(
                            "Screenshot: {}",
                            path.file_name().unwrap().to_string_lossy()
                        )))
                    });
                self.stage += 1;
                self.phase = 0;
            }
        }
        let w = &app.workspace;
        if w.binary.is_none()
            || w.analyzing
            || w.scanning
            || w.opening
            || w.page_loading
            || w.graph_loading.is_some()
            || w.page.is_none()
        {
            return;
        }
        self.first_ready
            .get_or_insert_with(|| self.started.elapsed().as_secs_f64() * 1000.0);
        if self.stage >= SIZES.len() * PANELS.len() {
            let output = self.output.join("renderer-metrics.json");
            let metrics = serde_json::json!({ "ready_ms": self.first_ready, "ui_cpu_ms": self.frames, "cached_navigation_ms": self.navigation, "note": "Actual native renderer. CPU time from eframe previous-frame info; excludes GPU/presentation. Repaint forced at ~60 Hz for display checks only. Scale 1.5 is application zoom, not an OS DPI change." });
            app.workspace
                .worker
                .submit(app.workspace.generation, move || {
                    std::fs::write(output, serde_json::to_vec_pretty(&metrics).unwrap())
                        .map_err(|e| e.to_string())?;
                    Ok(Event::Done)
                });
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        let (width, height, scale) = SIZES[self.stage / PANELS.len()];
        let panel = PANELS[self.stage % PANELS.len()];
        match self.phase {
            0 => {
                app.dock = default_dock();
                ctx.set_zoom_factor(scale);
                if let Some(address) = app
                    .workspace
                    .analysis
                    .as_ref()
                    .and_then(|a| a.functions.last())
                    .map(|f| f.address)
                {
                    let location = app.workspace.address_location(address);
                    app.workspace.navigate(location, true);
                }
                app.show_panel(panel);
                self.changed = Instant::now();
                self.phase = 1;
            }
            1 => {
                // Wait one frame after the zoom change before resizing.
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(
                    width / scale,
                    height / scale,
                )));
                self.changed = Instant::now();
                self.phase = 2;
            }
            2 => {
                if let Some(cpu) = cpu_seconds {
                    self.frames.push(serde_json::json!({"panel": format!("{panel:?}"), "width": width, "height": height, "scale": scale, "cpu_ms": cpu as f64 * 1000.0}));
                }
                if panel == Panel::Graph {
                    // Exercise the same transform used for pointer drag/zoom.
                    app.workspace.graph_pan.x += 0.25;
                    app.workspace.graph_zoom = (app.workspace.graph_zoom + 0.0005).min(1.1);
                }
                if panel == Panel::Disassembly
                    && let Some(address) = app
                        .workspace
                        .analysis
                        .as_ref()
                        .and_then(|a| {
                            a.instructions
                                .values()
                                .nth(self.navigation.len() % a.instructions.len().clamp(1, 100))
                        })
                        .map(|i| i.address)
                {
                    let start = Instant::now();
                    let location = app.workspace.address_location(address);
                    app.workspace.navigate(location, true);
                    self.navigation.push(start.elapsed().as_secs_f64() * 1000.0);
                }
                if self.changed.elapsed() > Duration::from_millis(400) {
                    let name = format!(
                        "{}x{}-{}-{:?}.png",
                        width as u32,
                        height as u32,
                        (scale * 100.0) as u32,
                        panel
                    );
                    ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::new(
                        name,
                    )));
                    self.phase = 3;
                }
            }
            _ => {}
        }
        // Keep the verification sequence independent of the command palette.
        app.workspace
            .actions
            .retain(|a| !matches!(a, Action::Palette));
    }
}
