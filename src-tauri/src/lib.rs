mod analysis;
mod commands;
mod state;

use state::AppState;
use tauri::Manager;

fn startup_binary_argument() -> Option<String> {
    std::env::args()
        .skip(1)
        .find(|argument| !argument.starts_with('-'))
        .filter(|argument| std::path::Path::new(argument).is_file())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .setup(|app| {
            if let Some(path) = startup_binary_argument() {
                app.state::<AppState>().set_startup_path(path);
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::open_binary,
            commands::close_binary,
            commands::take_startup_path,
            commands::disassemble,
            commands::read_hex,
            commands::extract_strings,
            commands::create_analysis_project,
            commands::open_analysis_project,
            commands::save_annotation,
            commands::set_project_address,
            commands::delete_annotation,
            analysis::analyze_binary,
            analysis::cancel_analysis,
            analysis::analysis_state,
            analysis::list_functions,
            analysis::function_at,
            analysis::function_cfg,
            analysis::xrefs_to,
            analysis::xrefs_from,
            analysis::rename_function,
        ])
        .run(tauri::generate_context!())
        .expect("failed to launch URA");
}
