use crate::analysis::display_parts;
use crate::state::AppState;
use std::path::PathBuf;
use tauri::State;
use ura_core::{
    analyze_path, parse_address, BinaryOpenResult, DisassemblyPage, HexPage, StringScanOptions,
    StringScanResult,
};
use ura_project::{
    create_project, delete_annotation as remove_annotation, open_project,
    save_annotation as persist_annotation, set_selected_address, Annotation, BinaryIdentity,
    ProjectInfo, ProjectSnapshot,
};

async fn run_blocking<T, F>(task: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(task)
        .await
        .map_err(|error| format!("background task failed: {}", error))?
}

#[tauri::command]
pub async fn open_binary(
    state: State<'_, AppState>,
    path: String,
) -> Result<BinaryOpenResult, String> {
    let state = state.inner().clone();
    run_blocking(move || {
        let binary_path = PathBuf::from(&path);
        let binary = analyze_path(&binary_path).map_err(|error| error.to_string())?;
        let result = binary.open_result();
        state.set_binary(binary);
        Ok(result)
    })
    .await
}

#[tauri::command]
pub fn close_binary(state: State<'_, AppState>) {
    state.clear_binary();
}

#[tauri::command]
pub fn take_startup_path(state: State<'_, AppState>) -> Option<String> {
    state.take_startup_path()
}

#[tauri::command]
pub async fn disassemble(
    state: State<'_, AppState>,
    address: String,
    count: usize,
) -> Result<DisassemblyPage, String> {
    let binary = state.binary().map_err(|error| error.to_string())?;
    let analysis = state.analysis();
    let names = state.function_names();
    let address_value = parse_address(&address).map_err(|error| error.to_string())?;
    run_blocking(move || {
        let mut page = binary
            .disassemble(address_value, count)
            .map_err(|error| error.to_string())?;
        if let Some(analysis) = analysis {
            for instruction in &mut page.instructions {
                let Some(target) = instruction.target.as_deref() else {
                    continue;
                };
                let Ok(target_value) = parse_address(target) else {
                    continue;
                };
                let Some(function) = analysis.function_containing(target_value) else {
                    continue;
                };
                instruction.target_name = Some(display_parts(function, &names).0);
            }
        }
        Ok(page)
    })
    .await
}

#[tauri::command]
pub async fn read_hex(
    state: State<'_, AppState>,
    offset: u64,
    length: usize,
) -> Result<HexPage, String> {
    let binary = state.binary().map_err(|error| error.to_string())?;
    run_blocking(move || {
        binary
            .read_hex(offset, length)
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
pub async fn extract_strings(
    state: State<'_, AppState>,
    min_length: usize,
    include_ascii: bool,
    include_utf16: bool,
) -> Result<StringScanResult, String> {
    let binary = state.binary().map_err(|error| error.to_string())?;
    run_blocking(move || {
        let options = StringScanOptions {
            min_length,
            ascii: include_ascii,
            utf16le: include_utf16,
            max_results: ura_core::MAX_STRINGS,
        };
        binary
            .extract_strings(&options)
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
pub async fn create_analysis_project(
    state: State<'_, AppState>,
    project_path: String,
    name: String,
) -> Result<ProjectInfo, String> {
    let binary = state.binary().map_err(|error| error.to_string())?;
    let info = run_blocking(move || {
        let view = binary.view();
        let identity = BinaryIdentity {
            binary_path: view.path,
            binary_hash: view.sha256,
            file_size: view.file_size,
            format: view.format,
            architecture: view.architecture,
        };
        create_project(PathBuf::from(&project_path).as_path(), &name, &identity)
            .map_err(|error| error.to_string())
    })
    .await?;
    state.set_name_context(info.binary_hash.clone(), Vec::new());
    Ok(info)
}

#[tauri::command]
pub async fn open_analysis_project(
    state: State<'_, AppState>,
    project_path: String,
) -> Result<ProjectSnapshot, String> {
    let snapshot = run_blocking(move || {
        open_project(PathBuf::from(&project_path).as_path()).map_err(|error| error.to_string())
    })
    .await?;
    state.set_name_context(
        snapshot.project.binary_hash.clone(),
        snapshot
            .function_names
            .iter()
            .map(|entry| (entry.address.clone(), entry.name.clone()))
            .collect::<Vec<_>>(),
    );
    Ok(snapshot)
}

#[tauri::command]
pub async fn save_annotation(
    project_path: String,
    address: String,
    label: Option<String>,
    note: String,
) -> Result<Annotation, String> {
    run_blocking(move || {
        persist_annotation(
            PathBuf::from(&project_path).as_path(),
            &address,
            label.as_deref(),
            &note,
        )
        .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
pub async fn set_project_address(project_path: String, address: String) -> Result<String, String> {
    run_blocking(move || {
        set_selected_address(PathBuf::from(&project_path).as_path(), &address)
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
pub async fn delete_annotation(project_path: String, annotation_id: i64) -> Result<(), String> {
    run_blocking(move || {
        remove_annotation(PathBuf::from(&project_path).as_path(), annotation_id)
            .map_err(|error| error.to_string())
    })
    .await
}
