use crate::state::AppState;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, State};
use ura_core::analysis::{
    analyze_binary_with_seeds as run_analysis_engine, AnalysisControl, AnalysisOptions,
    AnalysisProgress, AnalysisReport, AnalysisSeed, AnalysisStage, DataReferenceKind, Function,
    FunctionOrigin, ProgramAnalysis, Xref, XrefKind,
};
use ura_core::{format_address, parse_address};
use ura_project::{
    add_manual_function, delete_function_name, delete_manual_function,
    load_manual_functions_for_path, save_function_name,
};

const DEFAULT_FUNCTION_PAGE: usize = 200;
const MAX_FUNCTION_PAGE: usize = 500;
const DEFAULT_CFG_BLOCKS: usize = 240;
const MAX_CFG_BLOCKS: usize = 500;
const CFG_LINES_PER_BLOCK: usize = 12;
const DEFAULT_XREF_LIMIT: usize = 250;
const MAX_XREF_LIMIT: usize = 1_000;

async fn run_blocking<T, F>(task: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(task)
        .await
        .map_err(|error| format!("background task failed: {}", error))?
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisSummary {
    pub instruction_count: usize,
    pub function_count: usize,
    pub block_count: usize,
    pub xref_count: usize,
    pub data_xref_count: usize,
    pub cancelled: bool,
    pub truncated: bool,
    pub diagnostics_dropped: usize,
    pub elapsed_ms: u64,
    pub diagnostics: Vec<AnalysisDiagnosticView>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisDiagnosticView {
    pub address: Option<String>,
    pub message: String,
}

impl AnalysisSummary {
    fn from_report(report: &AnalysisReport) -> Self {
        Self {
            instruction_count: report.instruction_count,
            function_count: report.function_count,
            block_count: report.block_count,
            xref_count: report.xref_count,
            data_xref_count: report.data_xref_count,
            cancelled: report.cancelled,
            truncated: report.truncated,
            diagnostics_dropped: report.diagnostics_dropped,
            elapsed_ms: report.elapsed_ms,
            diagnostics: report
                .diagnostics
                .iter()
                .map(|diagnostic| AnalysisDiagnosticView {
                    address: diagnostic.address.clone(),
                    message: diagnostic.message.clone(),
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisStateView {
    pub summary: Option<AnalysisSummary>,
    pub running: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisRequest {
    #[serde(default)]
    pub max_instructions: Option<usize>,
    #[serde(default)]
    pub max_functions: Option<usize>,
    #[serde(default)]
    pub max_blocks: Option<usize>,
    #[serde(default)]
    pub follow_calls: Option<bool>,
    #[serde(default)]
    pub seed_symbols: Option<bool>,
}

impl AnalysisRequest {
    fn into_options(self) -> AnalysisOptions {
        let defaults = AnalysisOptions::default();
        AnalysisOptions {
            max_instructions: self.max_instructions.unwrap_or(defaults.max_instructions),
            max_functions: self.max_functions.unwrap_or(defaults.max_functions),
            max_blocks: self.max_blocks.unwrap_or(defaults.max_blocks),
            follow_calls: self.follow_calls.unwrap_or(defaults.follow_calls),
            seed_symbols: self.seed_symbols.unwrap_or(defaults.seed_symbols),
        }
        .normalized()
    }
}

struct EngineControl {
    app: AppHandle,
    cancel: Arc<AtomicBool>,
    last_report: Mutex<Instant>,
}

impl EngineControl {
    fn new(app: AppHandle, cancel: Arc<AtomicBool>) -> Self {
        Self {
            app,
            cancel,
            last_report: Mutex::new(Instant::now() - Duration::from_secs(1)),
        }
    }
}

impl AnalysisControl for EngineControl {
    fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    fn report(&self, progress: AnalysisProgress) {
        let throttled = matches!(progress.stage, AnalysisStage::Discovering);
        if throttled {
            if let Ok(mut last) = self.last_report.lock() {
                if last.elapsed() < Duration::from_millis(90) {
                    return;
                }
                *last = Instant::now();
            }
        }
        let _ = self.app.emit("analysis-progress", &progress);
    }
}

struct RunGuard {
    state: AppState,
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        self.state.finish_analysis();
    }
}

#[tauri::command]
pub async fn analyze_binary(
    app: AppHandle,
    state: State<'_, AppState>,
    options: Option<AnalysisRequest>,
    project_path: Option<String>,
) -> Result<AnalysisSummary, String> {
    execute_analysis(app, state.inner().clone(), options, project_path).await
}

async fn execute_analysis(
    app: AppHandle,
    state: AppState,
    options: Option<AnalysisRequest>,
    project_path: Option<String>,
) -> Result<AnalysisSummary, String> {
    let Some(cancel) = state.try_start_analysis() else {
        return Err("analysis is already running".to_string());
    };
    let _guard = RunGuard {
        state: state.clone(),
    };
    let binary = state.binary().map_err(|error| error.to_string())?;
    let binary_hash = state.binary_hash();
    let control = EngineControl::new(app, cancel);
    run_blocking(move || {
        let options = options
            .map(AnalysisRequest::into_options)
            .unwrap_or_default();
        let seeds = manual_seeds(project_path.as_deref())?;
        state.clear_analysis();
        let analysis = run_analysis_engine(&binary, &options, &seeds, &control);
        let summary = AnalysisSummary::from_report(&analysis.report);
        if binary_hash.is_some() && state.binary_hash() == binary_hash {
            state.set_analysis(analysis);
        }
        Ok(summary)
    })
    .await
}

fn manual_seeds(project_path: Option<&str>) -> Result<Vec<AnalysisSeed>, String> {
    let Some(project_path) = project_path.filter(|path| !path.trim().is_empty()) else {
        return Ok(Vec::new());
    };
    let entries = load_manual_functions_for_path(std::path::Path::new(project_path))
        .map_err(|error| error.to_string())?;
    Ok(entries
        .iter()
        .filter_map(|entry| {
            parse_address(&entry.address)
                .ok()
                .map(|address| AnalysisSeed {
                    address,
                    name: None,
                    origin: FunctionOrigin::UserDefined,
                })
        })
        .collect())
}

fn executable_address(state: &AppState, address: u64) -> Result<(), String> {
    let binary = state.binary().map_err(|error| error.to_string())?;
    let inside = binary.analysis().sections.iter().any(|section| {
        section.executable
            && address >= section.address
            && address < section.address.saturating_add(section.size)
    });
    if inside {
        Ok(())
    } else {
        Err(format!(
            "{} is not inside an executable section",
            format_address(address)
        ))
    }
}

#[tauri::command]
pub async fn create_manual_function(
    app: AppHandle,
    state: State<'_, AppState>,
    project_path: String,
    address: String,
) -> Result<AnalysisSummary, String> {
    let state = state.inner().clone();
    if project_path.trim().is_empty() {
        return Err("create or open a project to define functions".to_string());
    }
    let address = parse_address(&address).map_err(|error| error.to_string())?;
    executable_address(&state, address)?;
    let project = project_path.clone();
    let formatted = format_address(address);
    run_blocking(move || {
        add_manual_function(std::path::Path::new(&project), &formatted)
            .map_err(|error| error.to_string())
    })
    .await?;
    execute_analysis(app, state, None, Some(project_path)).await
}

#[tauri::command]
pub async fn remove_manual_function(
    app: AppHandle,
    state: State<'_, AppState>,
    project_path: String,
    address: String,
) -> Result<AnalysisSummary, String> {
    let state = state.inner().clone();
    if project_path.trim().is_empty() {
        return Err("create or open a project to delete functions".to_string());
    }
    let address = parse_address(&address).map_err(|error| error.to_string())?;
    let project = project_path.clone();
    let formatted = format_address(address);
    let removed = run_blocking(move || {
        delete_manual_function(std::path::Path::new(&project), &formatted)
            .map_err(|error| error.to_string())
    })
    .await?;
    if !removed {
        return Err(format!(
            "{} is not a user-defined function",
            format_address(address)
        ));
    }
    execute_analysis(app, state, None, Some(project_path)).await
}

#[tauri::command]
pub fn cancel_analysis(state: State<'_, AppState>) -> bool {
    state.cancel_analysis()
}

#[tauri::command]
pub fn analysis_state(state: State<'_, AppState>) -> AnalysisStateView {
    AnalysisStateView {
        summary: state
            .analysis()
            .map(|analysis| AnalysisSummary::from_report(&analysis.report)),
        running: state.analysis_running(),
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionSummary {
    pub address: String,
    pub name: String,
    pub symbol: Option<String>,
    pub custom_name: Option<String>,
    pub origin: String,
    pub verified: bool,
    pub end_address: String,
    pub size: u64,
    pub instruction_count: usize,
    pub block_count: usize,
    pub reference_count: usize,
    pub caller_count: usize,
    pub callee_count: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionRef {
    pub address: String,
    pub name: String,
    pub custom_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionDetail {
    #[serde(flatten)]
    pub function: FunctionSummary,
    pub callers: Vec<FunctionRef>,
    pub callees: Vec<FunctionRef>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionListPage {
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub functions: Vec<FunctionSummary>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FunctionQuery {
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub sort: Option<String>,
    #[serde(default)]
    pub descending: Option<bool>,
    #[serde(default)]
    pub offset: Option<usize>,
    #[serde(default)]
    pub limit: Option<usize>,
}

pub(crate) fn display_parts(
    function: &Function,
    names: &BTreeMap<u64, String>,
) -> (String, Option<String>) {
    let custom = names.get(&function.address).cloned();
    let name = custom
        .clone()
        .or_else(|| function.symbol.clone())
        .unwrap_or_else(|| function.fallback_name());
    (name, custom)
}

fn function_summary(function: &Function, names: &BTreeMap<u64, String>) -> FunctionSummary {
    let (name, custom_name) = display_parts(function, names);
    FunctionSummary {
        address: format_address(function.address),
        name,
        symbol: function.symbol.clone(),
        custom_name,
        origin: function.origin.name().to_string(),
        verified: function.verified(),
        end_address: format_address(function.end),
        size: function.size(),
        instruction_count: function.instruction_count,
        block_count: function.blocks.len(),
        reference_count: function.reference_count,
        caller_count: function.callers.len(),
        callee_count: function.callees.len(),
    }
}

fn function_ref(
    analysis: &ProgramAnalysis,
    names: &BTreeMap<u64, String>,
    address: u64,
) -> Option<FunctionRef> {
    let function = analysis.function_by_start(address)?;
    let (name, custom_name) = display_parts(function, names);
    Some(FunctionRef {
        address: format_address(function.address),
        name,
        custom_name,
    })
}

fn function_detail(
    analysis: &ProgramAnalysis,
    names: &BTreeMap<u64, String>,
    function: &Function,
) -> FunctionDetail {
    FunctionDetail {
        function: function_summary(function, names),
        callers: function
            .callers
            .iter()
            .filter_map(|address| function_ref(analysis, names, *address))
            .collect(),
        callees: function
            .callees
            .iter()
            .filter_map(|address| function_ref(analysis, names, *address))
            .collect(),
    }
}

fn current_analysis(state: &AppState) -> Result<Arc<ProgramAnalysis>, String> {
    state
        .analysis()
        .ok_or_else(|| "function analysis has not been run for this binary".to_string())
}

#[tauri::command]
pub fn list_functions(
    state: State<'_, AppState>,
    query: FunctionQuery,
) -> Result<FunctionListPage, String> {
    let limit = query
        .limit
        .unwrap_or(DEFAULT_FUNCTION_PAGE)
        .clamp(1, MAX_FUNCTION_PAGE);
    let offset = query.offset.unwrap_or(0);
    let Some(analysis) = state.analysis() else {
        return Ok(FunctionListPage {
            total: 0,
            offset,
            limit,
            functions: Vec::new(),
        });
    };
    let names = state.function_names();
    let needle = query
        .search
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_lowercase());
    let mut functions: Vec<FunctionSummary> = analysis
        .functions
        .iter()
        .map(|function| function_summary(function, &names))
        .filter(|summary| match &needle {
            None => true,
            Some(needle) => {
                summary.name.to_lowercase().contains(needle)
                    || summary.address.to_lowercase().contains(needle)
                    || summary
                        .symbol
                        .as_deref()
                        .is_some_and(|symbol| symbol.to_lowercase().contains(needle))
                    || summary.origin.to_lowercase().contains(needle)
            }
        })
        .collect();

    let sort = query.sort.as_deref().unwrap_or("address");
    match sort {
        "name" => functions.sort_by(|left, right| {
            left.name
                .to_lowercase()
                .cmp(&right.name.to_lowercase())
                .then_with(|| left.address.cmp(&right.address))
        }),
        "instructions" => functions.sort_by(|left, right| {
            right
                .instruction_count
                .cmp(&left.instruction_count)
                .then_with(|| left.address.cmp(&right.address))
        }),
        "blocks" => functions.sort_by(|left, right| {
            right
                .block_count
                .cmp(&left.block_count)
                .then_with(|| left.address.cmp(&right.address))
        }),
        "references" => functions.sort_by(|left, right| {
            right
                .reference_count
                .cmp(&left.reference_count)
                .then_with(|| left.address.cmp(&right.address))
        }),
        _ => functions.sort_by(|left, right| left.address.cmp(&right.address)),
    }
    if query.descending.unwrap_or(false) {
        functions.reverse();
    }

    let total = functions.len();
    let functions = functions.into_iter().skip(offset).take(limit).collect();
    Ok(FunctionListPage {
        total,
        offset,
        limit,
        functions,
    })
}

#[tauri::command]
pub fn function_at(
    state: State<'_, AppState>,
    address: String,
) -> Result<Option<FunctionDetail>, String> {
    let Some(analysis) = state.analysis() else {
        return Ok(None);
    };
    let address = ura_core::parse_address(&address).map_err(|error| error.to_string())?;
    let Some(function) = analysis.function_containing(address) else {
        return Ok(None);
    };
    let names = state.function_names();
    Ok(Some(function_detail(&analysis, &names, function)))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionCfg {
    pub function: FunctionSummary,
    pub total_blocks: usize,
    pub instruction_count: usize,
    pub truncated: bool,
    pub blocks: Vec<CfgBlockView>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CfgBlockView {
    pub address: String,
    pub end_address: String,
    pub instruction_count: usize,
    pub omitted_instructions: usize,
    pub lines: Vec<CfgLineView>,
    pub edges: Vec<CfgEdgeView>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CfgLineView {
    pub address: String,
    pub text: String,
    pub target_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CfgEdgeView {
    pub target: String,
    pub kind: String,
}

#[tauri::command]
pub fn function_cfg(
    state: State<'_, AppState>,
    address: String,
    max_blocks: Option<usize>,
) -> Result<FunctionCfg, String> {
    let analysis = current_analysis(&state)?;
    let address = ura_core::parse_address(&address).map_err(|error| error.to_string())?;
    let function = analysis
        .function_containing(address)
        .ok_or_else(|| format!("no function contains {}", format_address(address)))?;
    let names = state.function_names();
    let block_cap = max_blocks
        .unwrap_or(DEFAULT_CFG_BLOCKS)
        .clamp(1, MAX_CFG_BLOCKS);
    let total_blocks = function.blocks.len();
    let mut blocks = Vec::new();
    for block_address in function.blocks.iter().take(block_cap) {
        let Some(block) = analysis.blocks.get(block_address) else {
            continue;
        };
        let mut lines = Vec::new();
        for instruction_address in block.instructions.iter().take(CFG_LINES_PER_BLOCK) {
            let Some(instruction) = analysis.instructions.get(instruction_address) else {
                continue;
            };
            lines.push(CfgLineView {
                address: format_address(instruction.address),
                text: instruction.text(),
                target_name: instruction
                    .target
                    .and_then(|target| analysis.function_by_start(target))
                    .map(|function| display_parts(function, &names).0),
            });
        }
        let omitted_instructions = block.instructions.len().saturating_sub(CFG_LINES_PER_BLOCK);
        blocks.push(CfgBlockView {
            address: format_address(block.address),
            end_address: format_address(block.end),
            instruction_count: block.instructions.len(),
            omitted_instructions,
            lines,
            edges: block
                .successors
                .iter()
                .map(|edge| CfgEdgeView {
                    target: format_address(edge.target),
                    kind: edge.kind.name().to_string(),
                })
                .collect(),
        });
    }
    Ok(FunctionCfg {
        function: function_summary(function, &names),
        total_blocks,
        instruction_count: function.instruction_count,
        truncated: total_blocks > block_cap,
        blocks,
    })
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct XrefPage {
    pub total: usize,
    pub references: Vec<XrefView>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct XrefView {
    pub from: String,
    pub to: String,
    pub kind: String,
    pub data_kind: Option<String>,
    pub target_section: Option<String>,
    pub source_function: Option<FunctionRef>,
    pub target_function: Option<FunctionRef>,
}

fn xref_view(
    analysis: &ProgramAnalysis,
    names: &BTreeMap<u64, String>,
    sections: &[ura_core::binary::Section],
    xref: &Xref,
) -> XrefView {
    XrefView {
        from: format_address(xref.from),
        to: format_address(xref.to),
        kind: match xref.kind {
            XrefKind::Call => "call",
            XrefKind::Jump => "jump",
            XrefKind::ConditionalJump => "conditionalJump",
            XrefKind::Data => "data",
        }
        .to_string(),
        data_kind: xref.data_kind.map(|kind| {
            match kind {
                DataReferenceKind::RipRelative => "ripRelative",
                DataReferenceKind::PcRelative => "pcRelative",
                DataReferenceKind::Absolute => "absolute",
            }
            .to_string()
        }),
        target_section: sections
            .iter()
            .find(|section| {
                xref.to >= section.address && xref.to < section.address.saturating_add(section.size)
            })
            .map(|section| section.name.clone()),
        source_function: analysis
            .function_containing(xref.from)
            .and_then(|function| function_ref(analysis, names, function.address)),
        target_function: analysis
            .function_containing(xref.to)
            .and_then(|function| function_ref(analysis, names, function.address)),
    }
}

fn xref_page(
    state: &AppState,
    address: u64,
    limit: Option<usize>,
    incoming: bool,
) -> Result<XrefPage, String> {
    let analysis = current_analysis(state)?;
    let names = state.function_names();
    let sections = state
        .binary()
        .map(|binary| binary.analysis().sections.clone())
        .unwrap_or_default();
    let limit = limit.unwrap_or(DEFAULT_XREF_LIMIT).clamp(1, MAX_XREF_LIMIT);
    let references: Vec<&Xref> = if incoming {
        analysis.xrefs_to(address).collect()
    } else {
        analysis.xrefs_from(address).collect()
    };
    let total = references.len();
    let references = references
        .into_iter()
        .take(limit)
        .map(|xref| xref_view(&analysis, &names, &sections, xref))
        .collect();
    Ok(XrefPage { total, references })
}

#[tauri::command]
pub fn xrefs_to(
    state: State<'_, AppState>,
    address: String,
    limit: Option<usize>,
) -> Result<XrefPage, String> {
    let address = ura_core::parse_address(&address).map_err(|error| error.to_string())?;
    xref_page(&state, address, limit, true)
}

#[tauri::command]
pub fn xrefs_from(
    state: State<'_, AppState>,
    address: String,
    limit: Option<usize>,
) -> Result<XrefPage, String> {
    let address = ura_core::parse_address(&address).map_err(|error| error.to_string())?;
    xref_page(&state, address, limit, false)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenameResult {
    pub address: String,
    pub name: Option<String>,
}

#[tauri::command]
pub async fn rename_function(
    state: State<'_, AppState>,
    project_path: String,
    address: String,
    name: String,
) -> Result<RenameResult, String> {
    let state = state.inner().clone();
    let analysis = current_analysis(&state)?;
    let address = ura_core::parse_address(&address).map_err(|error| error.to_string())?;
    let function = analysis
        .function_containing(address)
        .ok_or_else(|| format!("no function contains {}", format_address(address)))?;
    let function_address = function.address;
    let trimmed = name.trim().to_string();
    if project_path.trim().is_empty() {
        return Err("create or open a project to rename functions".to_string());
    }
    let project_path = std::path::PathBuf::from(project_path);
    if trimmed.is_empty() {
        run_blocking(move || {
            delete_function_name(&project_path, &format_address(function_address))
                .map_err(|error| error.to_string())
        })
        .await?;
        state.set_function_name(function_address, None);
        return Ok(RenameResult {
            address: format_address(function_address),
            name: None,
        });
    }
    let saved = run_blocking(move || {
        save_function_name(&project_path, &format_address(function_address), &trimmed)
            .map_err(|error| error.to_string())
    })
    .await?;
    state.set_function_name(function_address, Some(saved.name.clone()));
    Ok(RenameResult {
        address: saved.address,
        name: Some(saved.name),
    })
}
