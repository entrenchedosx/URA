#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use ura_native::app::NativeApp;

fn main() -> eframe::Result {
    let started = std::time::Instant::now();
    std::panic::set_hook(Box::new(|info| {
        let path = std::env::temp_dir().join("ura-native-panic.log");
        let _ = std::fs::write(
            path,
            format!("{info}\n{}", std::backtrace::Backtrace::force_capture()),
        );
        eprintln!("{info}");
    }));
    let icon = image::load_from_memory(include_bytes!("../assets/icon.png"))
        .expect("bundled URA icon")
        .into_rgba8();
    let check_output = std::env::var_os("URA_DISPLAY_CHECK").map(std::path::PathBuf::from);
    let benchmark_output = std::env::var_os("URA_BENCHMARK_OUTPUT").map(std::path::PathBuf::from);
    let isolated_output = check_output.clone().or(benchmark_output.clone());
    if let Some(path) = &check_output {
        std::fs::create_dir_all(path).expect("create display check output");
    }
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("URA · Native analysis workspace")
            .with_app_id("ura-native")
            .with_inner_size(if benchmark_output.is_some() {
                [1480.0, 920.0]
            } else {
                [1440.0, 900.0]
            })
            .with_min_inner_size([900.0, 600.0])
            .with_icon(egui::IconData {
                width: icon.width(),
                height: icon.height(),
                rgba: icon.into_raw(),
            }),
        persist_window: isolated_output.is_none(),
        persistence_path: isolated_output.map(|p| p.join("verification-state.ron")),
        ..Default::default()
    };
    let startup = std::env::args_os().nth(1).map(std::path::PathBuf::from);
    eframe::run_native(
        "URA Native",
        options,
        Box::new(move |cc| {
            let mut app = NativeApp::new(cc, startup);
            app.display_check = ura_native::diagnostics::DisplayCheck::from_env(started);
            Ok(Box::new(app))
        }),
    )
}
