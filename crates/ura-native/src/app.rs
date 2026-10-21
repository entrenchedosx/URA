use crate::design::{self, Palette, Theme};
use crate::{
    graph::GraphLayout,
    navigation::{History, Location},
    worker::{Control, Event, TaskKind, Worker},
};
use eframe::egui::{self, Key, Modifiers, RichText};
use egui_dock::{DockArea, DockState, NodeIndex};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use ura_core::{
    BinaryView, DisassemblyPage, Function, LoadedBinary, ProgramAnalysis, StringScanOptions,
    StringScanResult, format_address, parse_address,
};
use ura_project::ProjectSnapshot;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Panel {
    Explorer,
    Disassembly,
    Functions,
    Graph,
    Hex,
    Strings,
    Xrefs,
    Overview,
    Inspector,
    Messages,
    GraphOverview,
    Ir,
}
impl Panel {
    pub const ALL: [Self; 12] = [
        Self::Explorer,
        Self::Disassembly,
        Self::Functions,
        Self::Graph,
        Self::Hex,
        Self::Strings,
        Self::Xrefs,
        Self::Overview,
        Self::Inspector,
        Self::Messages,
        Self::GraphOverview,
        Self::Ir,
    ];
    pub fn title(self) -> &'static str {
        match self {
            Self::Explorer => "Project structure",
            Self::Disassembly => "Disassembly",
            Self::Functions => "Functions",
            Self::Graph => "Graph",
            Self::Hex => "Hex View",
            Self::Strings => "Strings",
            Self::Xrefs => "Xrefs",
            Self::Overview => "Overview",
            Self::Inspector => "Inspector",
            Self::Messages => "Output",
            Self::GraphOverview => "Graph overview",
            Self::Ir => "IR",
        }
    }
    fn legacy(self) -> &'static str {
        match self {
            Self::Graph => "cfg",
            Self::Hex => "hex",
            Self::Disassembly => "disassembly",
            Self::Explorer => "explorer",
            Self::Functions => "explorer",
            Self::Strings => "strings",
            Self::Xrefs => "xrefs",
            Self::Overview => "overview",
            Self::Inspector => "inspector",
            Self::Messages => "messages",
            Self::GraphOverview => "graphOverview",
            Self::Ir => "ir",
        }
    }
    fn from_legacy(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.legacy() == s)
    }
}
pub fn default_dock() -> DockState<Panel> {
    let mut dock = DockState::new(vec![
        Panel::Disassembly,
        Panel::Graph,
        Panel::Hex,
        Panel::Strings,
        Panel::Xrefs,
        Panel::Overview,
        Panel::Inspector,
    ]);
    let [center, left] = dock.main_surface_mut().split_left(
        NodeIndex::root(),
        0.18,
        vec![Panel::Functions, Panel::Explorer],
    );
    dock.main_surface_mut()
        .split_below(left, 0.72, vec![Panel::GraphOverview]);
    dock.main_surface_mut()
        .split_below(center, 0.85, vec![Panel::Messages]);
    dock
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub font_size: f32,
    pub ui_font_size: f32,
    pub graph_font_size: f32,
    pub theme: Theme,
    pub row_height: f32,
    pub show_bytes: bool,
    pub hex_columns: usize,
    pub min_string: usize,
    pub ascii: bool,
    pub utf16: bool,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            font_size: 12.0,
            row_height: 18.0,
            ui_font_size: 12.0,
            graph_font_size: 11.0,
            theme: Theme::Classic,
            show_bytes: true,
            hex_columns: 16,
            min_string: 4,
            ascii: true,
            utf16: true,
        }
    }
}
impl Settings {
    fn normalize(&mut self) {
        if !self.font_size.is_finite() {
            self.font_size = 12.0;
        }
        if !self.row_height.is_finite() {
            self.row_height = 18.0;
        }
        self.font_size = self.font_size.clamp(10.0, 18.0);
        self.row_height = self.row_height.clamp(self.font_size + 4.0, 30.0);
        for (value, default) in [
            (&mut self.ui_font_size, 12.0),
            (&mut self.graph_font_size, 11.0),
        ] {
            if !value.is_finite() {
                *value = default;
            }
            *value = value.clamp(10.0, 18.0);
        }
        self.hex_columns = match self.hex_columns {
            8 | 16 | 32 => self.hex_columns,
            _ => 16,
        };
        self.min_string = self.min_string.clamp(2, 512);
    }
}
#[derive(Serialize, Deserialize)]
pub struct NativeView {
    pub dock: DockState<Panel>,
    pub history: History,
    pub location: Location,
    pub active: Panel,
    #[serde(default)]
    pub graph_function: Option<u64>,
    #[serde(default)]
    pub ir_ssa: bool,
}
#[derive(Default)]
pub struct Filter {
    pub query: String,
    pub indices: Vec<usize>,
    pub dirty: bool,
    pub sort: usize,
    pub descending: bool,
}

#[derive(Clone)]
pub enum Action {
    OpenDialog(bool),
    Open(PathBuf),
    NewProject,
    Close,
    Analyze,
    Scan,
    Cancel,
    Navigate(Location, bool),
    Show(Panel),
    TogglePanel(Panel),
    Back,
    Forward,
    ResetLayout,
    Palette,
    Settings,
    Rename,
    SaveRename,
    SaveAnnotation,
    DeleteAnnotation(i64),
    Manual(bool),
    Export,
    Save,
}
pub struct Workspace {
    pub worker: Worker,
    pub ctx: egui::Context,
    pub generation: u64,
    pub binary: Option<Arc<LoadedBinary>>,
    pub info: Option<BinaryView>,
    pub project: Option<(PathBuf, ProjectSnapshot)>,
    pub analysis: Option<Arc<ProgramAnalysis>>,
    pub analysis_revision: u64,
    pub strings: Option<StringScanResult>,
    pub page: Option<DisassemblyPage>,
    pub page_loading: bool,
    pub page_request: u64,
    pub next_page: bool,
    pub graph: BTreeMap<u64, GraphLayout>,
    pub graph_loading: Option<u64>,
    pub graph_zoom: f32,
    pub graph_pan: egui::Vec2,
    pub graph_function: Option<u64>,
    pub ir_ssa: bool,
    pub ir_key: Option<(u64, u64, bool)>,
    pub ir_loading: Option<(u64, u64, bool)>,
    pub ir_bundle: Option<Arc<ura_core::ir::inspect::Bundle>>,
    pub ir_rows: Vec<crate::worker::IrRow>,
    pub ir_error: Option<String>,
    pub cancel: Arc<AtomicBool>,
    pub progress: Arc<Mutex<Option<ura_core::AnalysisProgress>>>,
    pub analyzing: bool,
    pub opening: bool,
    pub scanning: bool,
    pub location: Location,
    pub history: History,
    pub active: Panel,
    pub settings: Settings,
    pub actions: Vec<Action>,
    pub restore: Option<String>,
    pub messages: Vec<(bool, String)>,
    pub names: BTreeMap<u64, String>,
    pub annotation_indices: BTreeMap<u64, usize>,
    pub function_filter: Filter,
    pub string_filter: Filter,
    pub explorer_filter: Filter,
    pub explorer_mode: usize,
    pub string_encoding: usize,
    pub xref_function: bool,
    pub xref_outgoing: bool,
    pub xref_filter: Filter,
    pub xref_key: Option<(u64, bool, bool)>,
    pub scroll_disassembly: bool,
    pub scroll_hex: bool,
    pub annotation_label: String,
    pub annotation_note: String,
    pub rename_open: bool,
    pub rename_value: String,
    pub rename_address: Option<u64>,
    pub palette_open: bool,
    pub palette_query: String,
    pub palette_focus: bool,
    pub palette_index: usize,
    pub palette_items: Vec<(String, String, Action)>,
    pub settings_open: bool,
    pub about_open: bool,
    pub icon: egui::TextureHandle,
    pub visible_panels: Vec<Panel>,
    pub last_error: Option<String>,
    pub recent: Vec<PathBuf>,
}

impl Workspace {
    fn new(ctx: egui::Context, settings: Settings, recent: Vec<PathBuf>) -> Self {
        let image = image::load_from_memory(include_bytes!("../assets/icon.png"))
            .expect("bundled icon")
            .into_rgba8();
        let icon = ctx.load_texture(
            "ura-official-icon",
            egui::ColorImage::from_rgba_unmultiplied(
                [image.width() as usize, image.height() as usize],
                image.as_raw(),
            ),
            Default::default(),
        );
        Self {
            worker: Worker::new(ctx.clone()),
            ctx,
            generation: 0,
            binary: None,
            info: None,
            project: None,
            analysis: None,
            analysis_revision: 0,
            strings: None,
            page: None,
            page_loading: false,
            page_request: 0,
            next_page: false,
            graph: BTreeMap::new(),
            graph_loading: None,
            graph_zoom: 1.0,
            graph_pan: egui::vec2(30.0, 25.0),
            graph_function: None,
            ir_ssa: false,
            ir_key: None,
            ir_loading: None,
            ir_bundle: None,
            ir_rows: vec![],
            ir_error: None,
            cancel: Arc::new(AtomicBool::new(false)),
            progress: Arc::new(Mutex::new(None)),
            analyzing: false,
            opening: false,
            scanning: false,
            location: Location::default(),
            history: History::default(),
            active: Panel::Disassembly,
            settings,
            actions: vec![],
            restore: None,
            messages: vec![(
                false,
                format!(
                    "URA {} · Native analysis workspace ready",
                    env!("CARGO_PKG_VERSION")
                ),
            )],
            names: BTreeMap::new(),
            annotation_indices: BTreeMap::new(),
            function_filter: Filter::default(),
            string_filter: Filter::default(),
            explorer_filter: Filter::default(),
            explorer_mode: 0,
            string_encoding: 0,
            xref_function: false,
            xref_outgoing: false,
            xref_filter: Filter::default(),
            xref_key: None,
            scroll_disassembly: false,
            scroll_hex: false,
            annotation_label: String::new(),
            annotation_note: String::new(),
            rename_open: false,
            rename_value: String::new(),
            rename_address: None,
            palette_open: false,
            palette_query: String::new(),
            palette_focus: false,
            palette_index: 0,
            palette_items: Vec::new(),
            settings_open: false,
            about_open: false,
            icon,
            visible_panels: vec![],
            last_error: None,
            recent,
        }
    }
    pub fn colors(&self) -> Palette {
        self.settings.theme.palette()
    }
    pub fn log(&mut self, error: bool, message: impl Into<String>) {
        let message = message.into();
        if error {
            self.last_error = Some(message.clone());
        }
        self.messages.push((error, message));
        if self.messages.len() > 500 {
            self.messages.remove(0);
        }
    }
    pub fn name(&self, f: &Function) -> String {
        self.names
            .get(&f.address)
            .cloned()
            .or_else(|| f.symbol.clone())
            .unwrap_or_else(|| f.fallback_name())
    }
    pub fn function(&self) -> Option<&Function> {
        self.analysis
            .as_ref()?
            .function_containing(self.location.address?)
    }
    pub fn address_location(&self, address: u64) -> Location {
        self.binary
            .as_ref()
            .map(|b| Location::address(b.analysis(), address))
            .unwrap_or(Location {
                address: Some(address),
                file_offset: None,
            })
    }
    pub fn navigate_address(&mut self, address: u64) {
        self.actions
            .push(Action::Navigate(self.address_location(address), true));
    }
    fn reset_data(&mut self) {
        self.binary = None;
        self.info = None;
        self.project = None;
        self.analysis = None;
        self.strings = None;
        self.page = None;
        self.graph.clear();
        self.graph_loading = None;
        self.graph_function = None;
        self.reset_ir();
        self.names.clear();
        self.annotation_indices.clear();
        self.history = History::default();
        self.location = Location::default();
        self.analyzing = false;
        self.scanning = false;
        self.page_loading = false;
        self.function_filter.dirty = true;
        self.string_filter.dirty = true;
        self.explorer_filter.dirty = true;
        self.xref_filter.dirty = true;
        self.xref_key = None;
        self.rename_open = false;
        self.annotation_label.clear();
        self.annotation_note.clear();
    }
    fn update_project(&mut self, path: PathBuf, snapshot: ProjectSnapshot) {
        self.annotation_indices = snapshot
            .annotations
            .iter()
            .enumerate()
            .filter_map(|(i, a)| Some((parse_address(&a.address).ok()?, i)))
            .collect();
        self.names = snapshot
            .function_names
            .iter()
            .filter_map(|n| Some((parse_address(&n.address).ok()?, n.name.clone())))
            .collect();
        self.project = Some((path, snapshot));
        self.function_filter.dirty = true;
        self.load_annotation();
    }
    fn load_annotation(&mut self) {
        let annotation = self.project.as_ref().and_then(|(_, p)| {
            self.location
                .address
                .and_then(|address| self.annotation_indices.get(&address))
                .and_then(|i| p.annotations.get(*i))
        });
        self.annotation_label = annotation.and_then(|a| a.label.clone()).unwrap_or_default();
        self.annotation_note = annotation.map(|a| a.note.clone()).unwrap_or_default();
    }
    pub fn navigate(&mut self, location: Location, record: bool) {
        if location.address.is_none() && location.file_offset.is_none() {
            return;
        }
        self.location = location;
        if record {
            self.history.visit(location);
        }
        self.scroll_disassembly = true;
        self.scroll_hex = true;
        self.xref_key = None;
        self.load_annotation();
        if let (Some(binary), Some(address)) = (&self.binary, location.address) {
            if binary
                .analysis()
                .code_section_containing_address(address)
                .is_some()
            {
                let cached = self.page.as_ref().is_some_and(|p| {
                    p.instructions
                        .iter()
                        .any(|i| parse_address(&i.address).ok() == Some(address))
                });
                if !cached {
                    self.request_page(address, false);
                }
            } else {
                self.actions.push(Action::Show(Panel::Hex));
            }
        } else {
            self.actions.push(Action::Show(Panel::Hex));
        }
        self.ensure_graph();
    }
    pub fn request_page(&mut self, address: u64, append: bool) {
        let Some(binary) = self.binary.clone() else {
            return;
        };
        self.page_request = address;
        self.page_loading = true;
        self.next_page = append;
        self.worker
            .submit_typed(self.generation, TaskKind::Page(address), move || {
                binary
                    .disassemble(address, 2000)
                    .map(|p| Event::Page(address, p))
                    .map_err(|e| e.to_string())
            });
    }
    pub fn ensure_graph(&mut self) {
        if self.analysis.is_none() {
            return;
        }
        let Some(function) = self.function().map(|f| f.address).or(self.graph_function) else {
            return;
        };
        if !self
            .analysis
            .as_ref()
            .is_some_and(|a| a.function_by_start(function).is_some())
        {
            // A retained graph can disappear when a manual seed is removed.
            self.graph_function = None;
            return;
        }
        if self.graph_function != Some(function) {
            self.graph_pan = egui::vec2(30.0, 25.0);
            self.graph_zoom = 1.0;
            self.graph_function = Some(function);
        }
        if self.graph.contains_key(&function) || self.graph_loading == Some(function) {
            return;
        }
        let Some(analysis) = self.analysis.clone() else {
            return;
        };
        self.graph_loading = Some(function);
        let revision = self.analysis_revision;
        self.worker
            .submit_typed(self.generation, TaskKind::Graph(function), move || {
                crate::graph::layout(&analysis, function).map(|graph| Event::Graph(revision, graph))
            });
    }
    fn reset_ir(&mut self) {
        self.ir_key = None;
        self.ir_loading = None;
        self.ir_bundle = None;
        self.ir_rows.clear();
        self.ir_error = None;
    }
    pub fn ensure_ir(&mut self) {
        if self.analyzing || self.opening {
            return;
        }
        let Some(function) = self.function().map(|f| f.address) else {
            return;
        };
        let key = (self.analysis_revision, function, self.ir_ssa);
        if self.ir_key == Some(key) || self.ir_loading.is_some() {
            return;
        }
        let (Some(binary), Some(analysis)) = (self.binary.clone(), self.analysis.clone()) else {
            return;
        };
        let cached = self
            .ir_bundle
            .as_ref()
            .filter(|b| b.raw.entry.0 == function)
            .cloned();
        self.cancel = Arc::new(AtomicBool::new(false));
        let control = Control {
            cancel: self.cancel.clone(),
            progress: self.progress.clone(),
            ctx: self.ctx.clone(),
            last: Mutex::new(Instant::now()),
        };
        self.ir_loading = Some(key);
        self.ir_error = None;
        self.worker
            .submit_typed(self.generation, TaskKind::Ir(key), move || {
                let bundle = match cached {
                    Some(b) => b,
                    None => Arc::new(ura_core::ir::inspect::analyze(
                        &binary, &analysis, function, &control,
                    )?),
                };
                let rows = bundle
                    .rows(key.2, 0, bundle.row_count(key.2))
                    .into_iter()
                    .map(|r| crate::worker::IrRow {
                        source: r.source.0,
                        text: r.text,
                        unsupported: r.unsupported,
                        block: matches!(r.detail, ura_core::ir::inspect::Detail::Block),
                    })
                    .collect();
                Ok(Event::Ir(key, bundle, rows))
            });
    }
    fn analyze(&mut self) {
        if self.analyzing || self.opening {
            return;
        }
        let Some(binary) = self.binary.clone() else {
            return;
        };
        let seeds = self
            .project
            .as_ref()
            .map(|(_, p)| {
                p.manual_functions
                    .iter()
                    .filter_map(|m| {
                        Some(ura_core::AnalysisSeed {
                            address: parse_address(&m.address).ok()?,
                            name: None,
                            origin: ura_core::FunctionOrigin::UserDefined,
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        self.cancel.store(true, Ordering::Relaxed);
        self.cancel = Arc::new(AtomicBool::new(false));
        *self.progress.lock().unwrap_or_else(|e| e.into_inner()) = None;
        let control = Control {
            cancel: self.cancel.clone(),
            progress: self.progress.clone(),
            ctx: self.ctx.clone(),
            last: Mutex::new(Instant::now() - Duration::from_secs(1)),
        };
        self.analyzing = true;
        self.log(false, "Analyzing functions, blocks and references…");
        self.worker
            .submit_typed(self.generation, TaskKind::Analysis, move || {
                Ok(Event::Analysis(Arc::new(
                    ura_core::analyze_binary_with_seeds(
                        &binary,
                        &Default::default(),
                        &seeds,
                        &control,
                    ),
                )))
            });
    }
    fn scan(&mut self) {
        if self.scanning {
            return;
        }
        let Some(binary) = self.binary.clone() else {
            return;
        };
        self.scanning = true;
        let options = StringScanOptions {
            min_length: self.settings.min_string,
            ascii: self.settings.ascii,
            utf16le: self.settings.utf16,
            ..Default::default()
        };
        self.worker
            .submit_typed(self.generation, TaskKind::Strings, move || {
                binary
                    .extract_strings(&options)
                    .map(Event::Strings)
                    .map_err(|e| e.to_string())
            });
    }
    fn poll(&mut self) {
        while let Ok(reply) = self.worker.receiver.try_recv() {
            if reply.generation != self.generation {
                continue;
            }
            if matches!(reply.kind,TaskKind::Ir((revision,_,_)) if revision!=self.analysis_revision)
            {
                continue;
            }
            match reply.result {
                Err(error) => {
                    match reply.kind {
                        TaskKind::Open => self.opening = false,
                        TaskKind::Analysis => self.analyzing = false,
                        TaskKind::Strings => self.scanning = false,
                        TaskKind::Page(address) if address == self.page_request => {
                            self.page_loading = false
                        }
                        TaskKind::Graph(function) if self.graph_loading == Some(function) => {
                            self.graph_loading = None
                        }
                        TaskKind::Ir(key) if self.ir_loading == Some(key) => {
                            self.ir_loading = None;
                            self.ir_key = Some(key);
                            self.ir_rows.clear();
                            self.ir_error = Some(error.clone());
                        }
                        _ => {}
                    }
                    self.log(true, error);
                }
                Ok(Event::Opened(opened)) => {
                    self.reset_data();
                    self.opening = false;
                    self.binary = opened.binary;
                    self.info = opened.info;
                    if let Some((path, snapshot)) = opened.project {
                        self.restore = snapshot.view_state.clone();
                        let selected = snapshot
                            .project
                            .selected_address
                            .as_deref()
                            .and_then(|v| parse_address(v).ok());
                        self.log(
                            snapshot.binary_status != "unchanged",
                            format!(
                                "Project {} · binary {}",
                                snapshot.project.name, snapshot.binary_status
                            ),
                        );
                        self.update_project(path.clone(), snapshot);
                        self.remember(path);
                        if let Some(address) = selected {
                            self.location = self.address_location(address);
                        }
                    } else if let Some(binary) = &self.binary {
                        self.remember(binary.path().to_path_buf());
                    }
                    if let Some(binary) = &self.binary {
                        if self.location.address.is_none() {
                            self.location = Location::address(
                                binary.analysis(),
                                binary
                                    .analysis()
                                    .entry_point
                                    .or_else(|| {
                                        binary
                                            .analysis()
                                            .executable_sections()
                                            .next()
                                            .map(|s| s.address)
                                    })
                                    .unwrap_or(binary.analysis().image_base),
                            );
                        }
                        self.log(
                            false,
                            format!(
                                "Opened {} · {} bytes",
                                binary.file_name(),
                                binary.bytes().len()
                            ),
                        );
                        if let Some(info) = &self.info {
                            let warnings = info.warnings.clone();
                            for w in warnings {
                                self.log(true, w);
                            }
                        }
                        self.history.visit(self.location);
                        if self.restore.is_none() {
                            self.navigate(self.location, false);
                        }
                        self.actions.push(Action::Analyze);
                        self.actions.push(Action::Scan);
                    }
                    self.explorer_filter.dirty = true;
                }
                Ok(Event::Analysis(analysis)) => {
                    self.analyzing = false;
                    let r = &analysis.report;
                    self.log(r.cancelled || r.truncated, format!("Analysis: {} functions · {} instructions · {} blocks · {} xrefs ({} data) · {} ms{}", r.function_count, r.instruction_count, r.block_count, r.xref_count, r.data_xref_count, r.elapsed_ms, if r.cancelled || r.truncated { " · PARTIAL" } else { "" }));
                    for d in &r.diagnostics {
                        self.log(
                            true,
                            format!(
                                "{} {}",
                                d.address.as_deref().unwrap_or("Analysis"),
                                d.message
                            ),
                        );
                    }
                    self.analysis = Some(analysis);
                    self.analysis_revision += 1;
                    self.reset_ir();
                    self.graph.clear();
                    self.graph_loading = None;
                    self.function_filter.dirty = true;
                    self.xref_key = None;
                    self.ensure_graph();
                }
                Ok(Event::Strings(strings)) => {
                    self.scanning = false;
                    self.log(
                        strings.truncated,
                        format!(
                            "Strings: {} ASCII · {} UTF-16LE{}",
                            strings.ascii_count,
                            strings.utf16_count,
                            if strings.truncated { " · partial" } else { "" }
                        ),
                    );
                    self.strings = Some(strings);
                    self.string_filter.dirty = true;
                }
                Ok(Event::Page(address, page)) => {
                    if address != self.page_request {
                        continue;
                    }
                    self.page_loading = false;
                    if self.next_page
                        && let Some(old) = &mut self.page
                        && old.instructions.len() < 16000
                    {
                        old.end_address = page.end_address;
                        old.has_more = page.has_more;
                        old.instructions.extend(page.instructions);
                    } else {
                        self.page = Some(page);
                    }
                }
                Ok(Event::Graph(revision, graph)) => {
                    if revision != self.analysis_revision {
                        continue;
                    }
                    if self.graph_loading == Some(graph.function) {
                        self.graph_loading = None;
                    }
                    if self.graph.len() >= 16 {
                        self.graph.clear();
                    }
                    self.graph.insert(graph.function, graph);
                }
                Ok(Event::Ir(key, bundle, rows)) => {
                    if key.0 != self.analysis_revision || self.ir_loading != Some(key) {
                        continue;
                    }
                    self.ir_loading = None;
                    self.ir_key = Some(key);
                    self.ir_bundle = Some(bundle);
                    self.ir_rows = rows;
                }
                Ok(Event::Project(path, snapshot, reanalyze)) => {
                    self.update_project(path, *snapshot);
                    self.log(false, "Project updated");
                    if reanalyze {
                        self.actions.push(Action::Analyze);
                    }
                }
                Ok(Event::Message(message)) => self.log(false, message),
                Ok(Event::Done) => {
                    self.opening = false;
                }
            }
        }
    }
    fn remember(&mut self, path: PathBuf) {
        self.recent.retain(|p| *p != path);
        self.recent.insert(0, path);
        self.recent.truncate(10);
    }
    pub fn edit_project(
        &mut self,
        edit: impl FnOnce(&std::path::Path) -> Result<(), String> + Send + 'static,
    ) {
        self.edit_project_with_analysis(false, edit);
    }
    pub fn edit_project_with_analysis(
        &mut self,
        reanalyze: bool,
        edit: impl FnOnce(&std::path::Path) -> Result<(), String> + Send + 'static,
    ) {
        let Some((path, _)) = &self.project else {
            self.log(true, "Create or open a project to save edits");
            return;
        };
        let path = path.clone();
        let snapshot = &self.project.as_ref().unwrap().1;
        let project = snapshot.project.clone();
        let binary_status = snapshot.binary_status.clone();
        self.worker.submit(self.generation, move || {
            edit(&path)?;
            // Identity was verified at open. Refresh only mutable project data;
            // hashing a 500 MiB image for every note would be unnecessary work.
            let snapshot = ura_project::ProjectSnapshot {
                project,
                binary_status,
                annotations: ura_project::load_annotations_for_path(&path)
                    .map_err(|e| e.to_string())?,
                function_names: ura_project::load_function_names_for_path(&path)
                    .map_err(|e| e.to_string())?,
                manual_functions: ura_project::load_manual_functions_for_path(&path)
                    .map_err(|e| e.to_string())?,
                view_state: ura_project::load_view_state_for_path(&path)
                    .map_err(|e| e.to_string())?,
            };
            Ok(Event::Project(path, Box::new(snapshot), reanalyze))
        });
    }
    pub fn keyboard(&mut self) {
        let ctx = self.ctx.clone();
        let shortcuts = [
            (
                Modifiers::CTRL | Modifiers::SHIFT,
                Key::O,
                Action::OpenDialog(true),
            ),
            (Modifiers::CTRL, Key::O, Action::OpenDialog(false)),
            (Modifiers::CTRL, Key::N, Action::NewProject),
            (Modifiers::CTRL, Key::K, Action::Palette),
            (Modifiers::CTRL, Key::G, Action::Palette),
            (Modifiers::CTRL, Key::Comma, Action::Settings),
            (Modifiers::CTRL, Key::S, Action::Save),
            (Modifiers::CTRL, Key::Num1, Action::Show(Panel::Disassembly)),
            (Modifiers::CTRL, Key::Num2, Action::Show(Panel::Hex)),
            (Modifiers::CTRL, Key::Num3, Action::Show(Panel::Strings)),
            (Modifiers::CTRL, Key::Num4, Action::Show(Panel::Overview)),
            (Modifiers::ALT, Key::ArrowLeft, Action::Back),
            (Modifiers::ALT, Key::ArrowRight, Action::Forward),
            (Modifiers::CTRL, Key::Enter, Action::SaveAnnotation),
        ];
        for (mods, key, action) in shortcuts {
            if ctx.input_mut(|i| i.consume_key(mods, key)) {
                self.actions.push(action);
            }
        }
        if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Escape)) {
            egui::Popup::close_all(&ctx);
            self.palette_open = false;
            self.settings_open = false;
            self.rename_open = false;
            self.about_open = false;
            self.last_error = None;
        }
        if self.palette_open
            || self.settings_open
            || self.rename_open
            || egui::Popup::is_any_open(&ctx)
            || ctx.egui_wants_keyboard_input()
        {
            return;
        }
        if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::F2)) {
            self.actions.push(Action::Rename);
        }
        if ctx.input(|i| i.modifiers.is_none())
            && ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Space))
            && matches!(self.active, Panel::Disassembly | Panel::Graph)
        {
            self.actions
                .push(Action::Show(if self.active == Panel::Graph {
                    Panel::Disassembly
                } else {
                    Panel::Graph
                }));
        }
        if self.active == Panel::Disassembly {
            for (key, delta) in [
                (Key::ArrowUp, -1),
                (Key::ArrowDown, 1),
                (Key::PageUp, -20),
                (Key::PageDown, 20),
            ] {
                if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, key))
                    && let Some(page) = &self.page
                {
                    let index = page
                        .instructions
                        .iter()
                        .position(|i| parse_address(&i.address).ok() == self.location.address)
                        .unwrap_or(0);
                    let index = index
                        .saturating_add_signed(delta)
                        .min(page.instructions.len().saturating_sub(1));
                    if let Some(i) = page.instructions.get(index)
                        && let Ok(address) = parse_address(&i.address)
                    {
                        self.navigate_address(address);
                    }
                }
            }
            if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Enter))
                && let Some(address) = self
                    .page
                    .as_ref()
                    .and_then(|p| {
                        p.instructions
                            .iter()
                            .find(|i| parse_address(&i.address).ok() == self.location.address)
                    })
                    .and_then(|i| i.target.as_deref())
                    .and_then(|t| parse_address(t).ok())
            {
                self.navigate_address(address);
            }
        }
    }
}

pub struct NativeApp {
    pub workspace: Workspace,
    pub dock: DockState<Panel>,
    last_save: Instant,
    pub display_check: Option<crate::diagnostics::DisplayCheck>,
    applied_style: Option<(Theme, u32, u32)>,
    idle_metrics: Option<crate::diagnostics::IdleMetrics>,
}
impl NativeApp {
    pub fn new(cc: &eframe::CreationContext<'_>, startup: Option<PathBuf>) -> Self {
        theme(&cc.egui_ctx);
        let mut settings: Settings = cc
            .storage
            .and_then(|s| eframe::get_value(s, "ura.settings.v1"))
            .unwrap_or_default();
        settings.normalize();
        design::apply(&cc.egui_ctx, &settings);
        let recent = cc
            .storage
            .and_then(|s| eframe::get_value(s, "ura.recent.v1"))
            .unwrap_or_default();
        let dock = cc
            .storage
            .and_then(|s| eframe::get_value(s, "ura.dock.v2"))
            .unwrap_or_else(default_dock);
        let mut app = Self {
            workspace: Workspace::new(cc.egui_ctx.clone(), settings, recent),
            dock,
            last_save: Instant::now(),
            display_check: None,
            applied_style: None,
            idle_metrics: crate::diagnostics::IdleMetrics::from_env(),
        };
        if let Some(path) = startup {
            app.workspace.actions.push(Action::Open(path));
        }
        app
    }
    pub fn show_panel(&mut self, panel: Panel) {
        if let Some(path) = self.dock.find_tab(&panel) {
            let _ = self.dock.set_active_tab(path);
            self.dock.set_focused_node_and_surface(path.node_path());
        } else {
            if panel == Panel::Ir
                && let Some(path) = self
                    .dock
                    .find_tab(&Panel::Disassembly)
                    .or_else(|| self.dock.find_tab(&Panel::Graph))
            {
                self.dock.set_focused_node_and_surface(path.node_path());
            }
            self.dock.push_to_focused_leaf(panel);
        }
        self.workspace.active = panel;
    }
    fn persist_project(&mut self) {
        let Some((path, snapshot)) = &self.workspace.project else {
            return;
        };
        let w = &self.workspace;
        let native = NativeView {
            dock: self.dock.clone(),
            history: w.history.clone(),
            location: w.location,
            active: w.active,
            graph_function: w.graph_function,
            ir_ssa: w.ir_ssa,
        };
        let mut value: serde_json::Value = snapshot
            .view_state
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .filter(|v: &serde_json::Value| v.is_object())
            .unwrap_or_else(|| serde_json::json!({}));
        value["version"] = 1.into();
        value["address"] = w.location.address.map(format_address).into();
        value["fileOffset"] = w.location.file_offset.map(format_address).into();
        value["activePanel"] = w.active.legacy().into();
        value["cfgAddress"] = w.graph_function.map(format_address).into();
        value["openPanels"] = self
            .dock
            .iter_all_tabs()
            .map(|(_, p)| p.legacy())
            .collect::<Vec<_>>()
            .into();
        value["history"] = w.history.entries.iter().map(|l| serde_json::json!({"address": l.address.map(format_address), "fileOffset": l.file_offset.map(format_address)})).collect();
        value["historyIndex"] = w.history.index.into();
        match serde_json::to_value(native) {
            Ok(native) => value["native"] = native,
            Err(error) => {
                self.workspace
                    .log(true, format!("Cannot save layout: {error}"));
                return;
            }
        }
        let path = path.clone();
        let address = w.location.address;
        let json = value.to_string();
        w.worker.submit(w.generation, move || {
            ura_project::save_view_state(&path, &json).map_err(|e| e.to_string())?;
            if let Some(address) = address {
                ura_project::set_selected_address(&path, &format_address(address))
                    .map_err(|e| e.to_string())?;
            }
            Ok(Event::Done)
        });
        self.last_save = Instant::now();
    }
    fn restore_project(&mut self) {
        let Some(raw) = self.workspace.restore.take() else {
            return;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
            return;
        };
        if let Some(native) = value
            .get("native")
            .and_then(|v| serde_json::from_value::<NativeView>(v.clone()).ok())
        {
            self.dock = native.dock;
            self.workspace.history = native.history;
            self.workspace.history.normalize();
            self.workspace.location = native.location;
            self.workspace.graph_function = native.graph_function;
            self.workspace.ir_ssa = native.ir_ssa;
            self.show_panel(native.active);
        } else {
            self.dock = default_dock();
            self.workspace.graph_function = value["cfgAddress"]
                .as_str()
                .and_then(|s| parse_address(s).ok());
            let address = value["address"]
                .as_str()
                .and_then(|v| parse_address(v).ok());
            let offset = value["fileOffset"]
                .as_str()
                .and_then(|v| parse_address(v).ok());
            if address.is_some() || offset.is_some() {
                self.workspace.location = Location {
                    address,
                    file_offset: offset,
                };
            }
            if let Some(history) = value["history"].as_array() {
                self.workspace.history.entries = history
                    .iter()
                    .map(|v| Location {
                        address: v["address"].as_str().and_then(|s| parse_address(s).ok()),
                        file_offset: v["fileOffset"].as_str().and_then(|s| parse_address(s).ok()),
                    })
                    .collect();
                self.workspace.history.index = value["historyIndex"].as_u64().unwrap_or(0) as usize;
                self.workspace.history.normalize();
            }
            if let Some(panel) = value["activePanel"].as_str().and_then(Panel::from_legacy) {
                self.show_panel(panel);
            }
        }
        self.workspace.navigate(self.workspace.location, false);
    }
    fn process_actions(&mut self) {
        // Navigation can produce a panel-focus action. Process a bounded number
        // of rounds, with no recursive UI borrows.
        for _ in 0..4 {
            let actions = std::mem::take(&mut self.workspace.actions);
            if actions.is_empty() {
                break;
            }
            for action in actions {
                match action {
                    Action::Show(panel) => self.show_panel(panel),
                    Action::TogglePanel(panel) => {
                        if let Some(path) = self.dock.find_tab(&panel) {
                            self.dock.remove_tab(path);
                        } else {
                            self.show_panel(panel);
                        }
                    }
                    Action::ResetLayout => self.dock = default_dock(),
                    Action::Save => self.persist_project(),
                    Action::Open(path) => {
                        self.persist_project();
                        let w = &mut self.workspace;
                        w.cancel.store(true, Ordering::Relaxed);
                        w.generation += 1;
                        w.opening = true;
                        w.analyzing = false;
                        w.scanning = false;
                        w.page_loading = false;
                        w.graph_loading = None;
                        w.worker
                            .submit_typed(w.generation, TaskKind::Open, move || {
                                crate::worker::open(path)
                            });
                    }
                    Action::OpenDialog(project) => {
                        self.persist_project();
                        let w = &mut self.workspace;
                        if w.opening {
                            continue;
                        }
                        w.cancel.store(true, Ordering::Relaxed);
                        w.generation += 1;
                        w.opening = true;
                        w.analyzing = false;
                        w.scanning = false;
                        w.page_loading = false;
                        w.graph_loading = None;
                        w.worker
                            .submit_typed(w.generation, TaskKind::Open, move || {
                                let dialog = rfd::FileDialog::new().set_title(if project {
                                    "Open URA project"
                                } else {
                                    "Open executable image"
                                });
                                let dialog = if project {
                                    dialog.add_filter("URA project", &["ura"])
                                } else {
                                    dialog
                                };
                                match dialog.pick_file() {
                                    Some(path) => crate::worker::open(path),
                                    None => Ok(Event::Done),
                                }
                            });
                    }
                    Action::Close => {
                        self.persist_project();
                        let w = &mut self.workspace;
                        w.cancel.store(true, Ordering::Relaxed);
                        w.generation += 1;
                        w.reset_data();
                        w.opening = false;
                    }
                    Action::NewProject => {
                        self.persist_project();
                        let w = &mut self.workspace;
                        let Some(info) = &w.info else {
                            continue;
                        };
                        let identity = ura_project::BinaryIdentity {
                            binary_path: info.path.clone(),
                            binary_hash: info.sha256.clone(),
                            file_size: info.file_size,
                            format: info.format.clone(),
                            architecture: info.architecture.clone(),
                        };
                        let name = info.file_name.clone();
                        w.worker.submit(w.generation, move || {
                            let Some(path) = rfd::FileDialog::new()
                                .set_title("Create analysis project")
                                .add_filter("URA project", &["ura"])
                                .set_file_name(format!("{name}.ura"))
                                .save_file()
                            else {
                                return Ok(Event::Done);
                            };
                            ura_project::create_project(&path, &name, &identity)
                                .map_err(|e| e.to_string())?;
                            Ok(Event::Project(
                                path.clone(),
                                Box::new(
                                    ura_project::open_project(&path).map_err(|e| e.to_string())?,
                                ),
                                false,
                            ))
                        });
                    }
                    Action::Navigate(location, record) => self.workspace.navigate(location, record),
                    Action::Back | Action::Forward => {
                        let delta = if matches!(action, Action::Back) {
                            -1
                        } else {
                            1
                        };
                        if let Some(location) = self.workspace.history.step(delta) {
                            self.workspace.navigate(location, false);
                        }
                    }
                    Action::Analyze => self.workspace.analyze(),
                    Action::Scan => self.workspace.scan(),
                    Action::Cancel => {
                        self.workspace.cancel.store(true, Ordering::Relaxed);
                    }
                    Action::Palette => {
                        let w = &mut self.workspace;
                        w.palette_open = true;
                        w.palette_query.clear();
                        w.palette_index = 0;
                        w.palette_focus = true;
                    }
                    Action::Settings => self.workspace.settings_open = true,
                    Action::Rename => {
                        let w = &mut self.workspace;
                        if let Some((address, name)) = w.function().map(|f| (f.address, w.name(f)))
                        {
                            w.rename_address = Some(address);
                            w.rename_value = name;
                            w.rename_open = true;
                        } else {
                            w.log(true, "Select an analyzed function to rename");
                        }
                    }
                    Action::SaveRename => {
                        let w = &mut self.workspace;
                        if let Some(address) = w.rename_address {
                            let name = w.rename_value.trim().to_string();
                            w.edit_project(move |p| {
                                if name.is_empty() {
                                    ura_project::delete_function_name(p, &format_address(address))
                                        .map_err(|e| e.to_string())
                                } else {
                                    ura_project::save_function_name(
                                        p,
                                        &format_address(address),
                                        &name,
                                    )
                                    .map(|_| ())
                                    .map_err(|e| e.to_string())
                                }
                            });
                            w.rename_open = false;
                        }
                    }
                    Action::SaveAnnotation => {
                        let w = &mut self.workspace;
                        if let Some(address) = w.location.address {
                            let label = w.annotation_label.clone();
                            let note = w.annotation_note.clone();
                            w.edit_project(move |p| {
                                ura_project::save_annotation(
                                    p,
                                    &format_address(address),
                                    Some(&label),
                                    &note,
                                )
                                .map(|_| ())
                                .map_err(|e| e.to_string())
                            });
                        } else {
                            w.log(true, "Annotations require a mapped virtual address");
                        }
                    }
                    Action::DeleteAnnotation(id) => self.workspace.edit_project(move |p| {
                        ura_project::delete_annotation(p, id).map_err(|e| e.to_string())
                    }),
                    Action::Manual(add) => {
                        let w = &mut self.workspace;
                        if w.analyzing {
                            w.log(
                                true,
                                "Wait for analysis to finish before changing function seeds",
                            );
                            continue;
                        }
                        let address = if add {
                            w.location.address
                        } else {
                            w.function().map(|f| f.address)
                        };
                        let Some(address) = address else {
                            continue;
                        };
                        if !w.binary.as_ref().is_some_and(|b| {
                            b.analysis()
                                .code_section_containing_address(address)
                                .is_some()
                        }) {
                            w.log(true, "Function seeds require an executable address");
                            continue;
                        }
                        w.edit_project_with_analysis(true, move |p| {
                            if add {
                                ura_project::add_manual_function(p, &format_address(address))
                                    .map(|_| ())
                                    .map_err(|e| e.to_string())
                            } else {
                                match ura_project::delete_manual_function(
                                    p,
                                    &format_address(address),
                                )
                                .map_err(|e| e.to_string())?
                                {
                                    true => Ok(()),
                                    false => {
                                        Err("The selected function is not user-defined".into())
                                    }
                                }
                            }
                        });
                    }
                    Action::Export => {
                        let w = &mut self.workspace;
                        if let Some((path, _)) = &w.project {
                            let path = path.clone();
                            w.worker.submit(w.generation, move || {
                                let Some(destination) = rfd::FileDialog::new()
                                    .set_title("Export annotations")
                                    .add_filter("JSON", &["json"])
                                    .set_file_name("ura-annotations.json")
                                    .save_file()
                                else {
                                    return Ok(Event::Done);
                                };
                                let result = ura_project::export_annotations(&path, &destination)
                                    .map_err(|e| e.to_string())?;
                                Ok(Event::Message(format!(
                                    "Exported {} annotations, {} names, {} manual functions to {}",
                                    result.annotation_count,
                                    result.function_name_count,
                                    result.manual_function_count,
                                    result.path
                                )))
                            });
                        } else {
                            w.log(true, "Create or open a project to export annotations");
                        }
                    }
                }
            }
        }
    }
}

impl eframe::App for NativeApp {
    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        if let Some(metrics) = &mut self.idle_metrics {
            metrics.record(ui.ctx(), frame.info().cpu_usage);
        }
        self.workspace.settings.normalize();
        let s = &self.workspace.settings;
        let style_key = (s.theme, s.ui_font_size.to_bits(), s.font_size.to_bits());
        if self.applied_style != Some(style_key) {
            design::apply(ui.ctx(), s);
            self.applied_style = Some(style_key);
        }
        self.workspace.poll();
        self.restore_project();
        self.workspace.keyboard();
        self.process_actions();
        let ctx = ui.ctx().clone();
        self.workspace.visible_panels = self.dock.iter_all_tabs().map(|(_, tab)| *tab).collect();
        if let Some(mut check) = self.display_check.take() {
            check.update(self, &ctx, frame.info().cpu_usage);
            self.display_check = Some(check);
        }
        egui::Panel::top("toolbar").show(ui, |ui| self.workspace.toolbar(ui));
        egui::Panel::bottom("status")
            .exact_size(design::STATUS_HEIGHT)
            .show(ui, |ui| self.workspace.status(ui));
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(self.workspace.colors().bg))
            .show(ui, |ui| {
                let mut style = egui_dock::Style::from_egui(ui.style());
                style.tab_bar.height = design::TAB_HEIGHT;
                style.tab_bar.bg_fill = self.workspace.colors().panel;
                style.tab.active.bg_fill = self.workspace.colors().bg;
                style.tab.focused.bg_fill = self.workspace.colors().bg;
                style.tab.focused.text_color = self.workspace.colors().accent;
                style.tab.tab_body.bg_fill = self.workspace.colors().bg;
                style.tab.tab_body.inner_margin = egui::Margin::same(3);
                style.separator.width = 2.0;
                style.separator.color_idle = self.workspace.colors().border;
                DockArea::new(&mut self.dock)
                    .style(style)
                    .show_inside(ui, &mut self.workspace);
            });
        self.workspace.dialogs(&ctx);
        if let Some(path) =
            ctx.input(|i| i.raw.dropped_files.first().map(|f| f.path().to_path_buf()))
        {
            self.workspace.actions.push(Action::Open(path));
        }
        self.process_actions();
    }
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, "ura.settings.v1", &self.workspace.settings);
        eframe::set_value(storage, "ura.recent.v1", &self.workspace.recent);
        eframe::set_value(storage, "ura.dock.v2", &self.dock);
        self.persist_project();
    }
    fn auto_save_interval(&self) -> Duration {
        Duration::from_secs(10)
    }
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.workspace.cancel.store(true, Ordering::Relaxed);
    }
}

fn theme(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    if let Some(windows) = std::env::var_os("WINDIR") {
        for (name, file, family) in [
            ("ura-ui", "segoeui.ttf", egui::FontFamily::Proportional),
            ("ura-code", "consola.ttf", egui::FontFamily::Monospace),
        ] {
            if let Ok(bytes) = std::fs::read(PathBuf::from(&windows).join("Fonts").join(file)) {
                fonts
                    .font_data
                    .insert(name.into(), egui::FontData::from_owned(bytes).into());
                fonts
                    .families
                    .entry(family)
                    .or_default()
                    .insert(0, name.into());
            }
        }
    }
    ctx.set_fonts(fonts);
    design::apply(ctx, &Settings::default());
}

pub fn mono(text: impl Into<String>) -> RichText {
    RichText::new(text).monospace()
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui_dock::TabViewer;

    fn test_app() -> NativeApp {
        let ctx = egui::Context::default();
        theme(&ctx);
        let binary = Arc::new(
            ura_core::analyze_path(std::path::Path::new("../../tests/fixtures/ura64.exe")).unwrap(),
        );
        let analysis = Arc::new(ura_core::analyze_functions(
            &binary,
            &Default::default(),
            &(),
        ));
        let address = binary.analysis().entry_point.unwrap();
        let mut workspace = Workspace::new(ctx, Settings::default(), vec![]);
        workspace.info = Some(binary.view());
        workspace.location = Location::address(binary.analysis(), address);
        workspace.page = Some(binary.disassemble(address, 320).unwrap());
        workspace.strings = Some(binary.extract_strings(&Default::default()).unwrap());
        workspace.analysis = Some(analysis.clone());
        workspace.binary = Some(binary);
        workspace.history.visit(workspace.location);
        workspace.function_filter.dirty = true;
        workspace.string_filter.dirty = true;
        workspace.explorer_filter.dirty = true;
        for f in &analysis.functions {
            workspace.graph.insert(
                f.address,
                crate::graph::layout(&analysis, f.address).unwrap(),
            );
        }
        NativeApp {
            workspace,
            dock: default_dock(),
            last_save: Instant::now(),
            display_check: None,
            applied_style: None,
            idle_metrics: crate::diagnostics::IdleMetrics::from_env(),
        }
    }
    fn pump(app: &mut NativeApp, condition: impl Fn(&NativeApp) -> bool) {
        let started = Instant::now();
        loop {
            app.workspace.poll();
            app.process_actions();
            if condition(app) {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "Timed out waiting for background task"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    #[test]
    fn every_panel_tessellates_at_required_sizes_and_scale() {
        let mut app = test_app();
        app.workspace.ensure_ir();
        pump(&mut app, |a| a.workspace.ir_key.is_some());
        let ctx = app.workspace.ctx.clone();
        for (theme, width, height, scale) in
            [Theme::Classic, Theme::Dark].into_iter().flat_map(|theme| {
                [
                    (1280.0, 720.0, 1.0),
                    (1440.0, 900.0, 1.0),
                    (1920.0, 1080.0, 1.0),
                    (1920.0, 1080.0, 1.5),
                ]
                .map(move |(w, h, s)| (theme, w, h, s))
            })
        {
            app.workspace.settings.theme = theme;
            design::apply(&ctx, &app.workspace.settings);
            ctx.set_pixels_per_point(scale);
            for mut panel in Panel::ALL {
                let mut output = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(width / scale, height / scale),
                        )),
                        ..Default::default()
                    },
                    |ui| {
                        egui::CentralPanel::default()
                            .show(ui, |ui| app.workspace.ui(ui, &mut panel));
                    },
                );
                output.textures_delta.clear();
                assert!(!output.shapes.is_empty(), "Empty {panel:?}");
                let meshes = ctx.tessellate(output.shapes, scale);
                for clipped in meshes {
                    if let egui::epaint::Primitive::Mesh(mesh) = clipped.primitive {
                        for vertex in mesh.vertices {
                            assert!(
                                vertex.pos.x.is_finite() && vertex.pos.y.is_finite(),
                                "Invalid vertex in {panel:?}"
                            );
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn native_ir_worker_matches_core_and_rejects_stale_analysis_results() {
        let mut app = test_app();
        assert!(app.dock.find_tab(&Panel::Ir).is_none());
        app.show_panel(Panel::Functions);
        app.show_panel(Panel::Ir);
        assert_eq!(
            app.dock.find_tab(&Panel::Ir).unwrap().node_path(),
            app.dock.find_tab(&Panel::Disassembly).unwrap().node_path()
        );
        let expected = ura_core::ir::inspect::analyze(
            app.workspace.binary.as_ref().unwrap(),
            app.workspace.analysis.as_ref().unwrap(),
            0x140001000,
            &(),
        )
        .unwrap();
        for ssa in [false, true] {
            app.workspace.ir_ssa = ssa;
            app.workspace.ensure_ir();
            pump(&mut app, |a| {
                a.workspace.ir_key.is_some_and(|k| k.2 == ssa) && a.workspace.ir_loading.is_none()
            });
            assert_eq!(
                app.workspace
                    .ir_rows
                    .iter()
                    .map(|r| &r.text)
                    .collect::<Vec<_>>(),
                expected
                    .rows(ssa, 0, expected.row_count(ssa))
                    .iter()
                    .map(|r| &r.text)
                    .collect::<Vec<_>>()
            );
        }
        let key = app.workspace.ir_key.unwrap();
        app.workspace.analysis_revision += 1;
        app.workspace.reset_ir();
        app.workspace
            .worker
            .submit_typed(app.workspace.generation, TaskKind::Ir(key), || {
                Err("stale IR failure".into())
            });
        app.workspace.worker.submit(app.workspace.generation, || {
            Ok(Event::Message("IR barrier".into()))
        });
        pump(&mut app, |a| {
            a.workspace.messages.iter().any(|(_, s)| s == "IR barrier")
        });
        assert!(app.workspace.ir_key.is_none());
        assert!(
            !app.workspace
                .messages
                .iter()
                .any(|(_, s)| s == "stale IR failure")
        );
    }
    #[test]
    fn project_edits_manual_seeds_and_native_state_survive_reopen() {
        let mut app = test_app();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("native.ura");
        let info = app.workspace.info.as_ref().unwrap();
        let identity = ura_project::BinaryIdentity {
            binary_path: std::fs::canonicalize(&info.path)
                .unwrap()
                .to_string_lossy()
                .into(),
            binary_hash: info.sha256.clone(),
            file_size: info.file_size,
            format: info.format.clone(),
            architecture: info.architecture.clone(),
        };
        ura_project::create_project(&path, "Native integration", &identity).unwrap();
        app.workspace
            .update_project(path.clone(), ura_project::open_project(&path).unwrap());
        app.workspace.annotation_label = "entry_label".into();
        app.workspace.annotation_note = "Persisted native annotation".into();
        app.workspace.actions.push(Action::SaveAnnotation);
        app.process_actions();
        pump(&mut app, |a| {
            a.workspace.project.as_ref().unwrap().1.annotations.len() == 1
        });
        app.workspace.actions.push(Action::Rename);
        app.process_actions();
        app.workspace.rename_value = "native_entry".into();
        app.workspace.actions.push(Action::SaveRename);
        app.process_actions();
        pump(&mut app, |a| {
            a.workspace.names.values().any(|s| s == "native_entry")
        });
        let manual = 0x140001014;
        app.workspace
            .navigate(app.workspace.address_location(manual), true);
        app.workspace.actions.push(Action::Manual(true));
        app.process_actions();
        pump(&mut app, |a| {
            !a.workspace.analyzing
                && a.workspace
                    .analysis
                    .as_ref()
                    .is_some_and(|p| p.function_by_start(manual).is_some())
        });
        app.show_panel(Panel::Graph);
        app.persist_project();
        app.workspace.worker.submit(app.workspace.generation, || {
            Ok(Event::Message("flush".into()))
        });
        pump(&mut app, |a| {
            a.workspace.messages.iter().any(|(_, s)| s == "flush")
        });
        let snapshot = ura_project::open_project(&path).unwrap();
        assert_eq!(snapshot.annotations[0].note, "Persisted native annotation");
        assert_eq!(snapshot.function_names[0].name, "native_entry");
        assert_eq!(snapshot.manual_functions.len(), 1);
        let mut reopened = test_app();
        reopened.workspace.restore = snapshot.view_state;
        reopened.restore_project();
        assert_eq!(reopened.workspace.location.address, Some(manual));
        assert_eq!(reopened.workspace.active, Panel::Graph);
        assert_eq!(reopened.dock.iter_all_tabs().count(), 11);
        assert!(reopened.dock.find_tab(&Panel::Ir).is_none());
        assert!(reopened.workspace.history.entries.len() >= 2);
        let destination = dir.path().join("annotations.json");
        let export = ura_project::export_annotations(&path, &destination).unwrap();
        assert_eq!(
            (
                export.annotation_count,
                export.function_name_count,
                export.manual_function_count
            ),
            (1, 1, 1)
        );
        app.workspace.actions.push(Action::Manual(false));
        app.process_actions();
        pump(&mut app, |a| {
            !a.workspace.analyzing
                && a.workspace
                    .project
                    .as_ref()
                    .unwrap()
                    .1
                    .manual_functions
                    .is_empty()
                && a.workspace
                    .analysis
                    .as_ref()
                    .is_some_and(|p| p.function_by_start(manual).is_none())
        });
        let annotation_id = app.workspace.project.as_ref().unwrap().1.annotations[0].id;
        app.workspace
            .actions
            .push(Action::DeleteAnnotation(annotation_id));
        app.process_actions();
        pump(&mut app, |a| {
            a.workspace
                .project
                .as_ref()
                .unwrap()
                .1
                .annotations
                .is_empty()
        });
    }
    #[test]
    fn restores_legacy_v04_navigation_without_changing_schema() {
        let mut app = test_app();
        app.workspace.restore = Some(serde_json::json!({"version":1,"address":"0x140001020","fileOffset":"0x220","activePanel":"hex","history":[{"address":"0x140001000","fileOffset":"0x200"},{"address":"0x140001020","fileOffset":"0x220"}],"historyIndex":1}).to_string());
        app.restore_project();
        assert_eq!(app.workspace.location.address, Some(0x140001020));
        assert_eq!(app.workspace.active, Panel::Hex);
        assert_eq!(
            app.workspace.history.step(-1).unwrap().address,
            Some(0x140001000)
        );
        assert_eq!(ura_project::SCHEMA_VERSION, 3);
    }
    #[test]
    fn stale_open_results_do_not_replace_current_binary() {
        let mut app = test_app();
        let selected = app.workspace.location;
        app.workspace
            .worker
            .submit(app.workspace.generation + 1, || {
                Ok(Event::Page(
                    0,
                    ura_core::analyze_path(std::path::Path::new("../../tests/fixtures/ura64.exe"))
                        .unwrap()
                        .disassemble(0x140001020, 1)
                        .unwrap(),
                ))
            });
        app.workspace.worker.submit(app.workspace.generation, || {
            Ok(Event::Message("stale checked".into()))
        });
        pump(&mut app, |a| {
            a.workspace
                .messages
                .iter()
                .any(|(_, s)| s == "stale checked")
        });
        assert_eq!(app.workspace.location, selected);
        assert_eq!(
            app.workspace.page.as_ref().unwrap().start_address,
            "0x140001000"
        );
    }
    #[test]
    fn old_analysis_graph_cannot_replace_current_geometry() {
        let mut app = test_app();
        app.workspace.analysis_revision = 2;
        let address = app.workspace.location.address.unwrap();
        let mut graph =
            crate::graph::layout(app.workspace.analysis.as_ref().unwrap(), address).unwrap();
        graph.nodes[0].x = 999.0;
        app.workspace.graph_loading = Some(address);
        app.workspace
            .worker
            .submit(app.workspace.generation, move || Ok(Event::Graph(1, graph)));
        app.workspace.worker.submit(app.workspace.generation, || {
            Ok(Event::Message("graph checked".into()))
        });
        pump(&mut app, |a| {
            a.workspace
                .messages
                .iter()
                .any(|(_, s)| s == "graph checked")
        });
        assert_ne!(app.workspace.graph[&address].nodes[0].x, 999.0);
        assert_eq!(app.workspace.graph_loading, Some(address));
    }
}
