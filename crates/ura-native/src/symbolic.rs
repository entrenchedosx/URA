use crate::{
    app::Workspace,
    worker::{Control, DecompKey, Event, SymbolicKey, TaskKind},
};
use eframe::egui;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
use ura_core::symbolic::{self, Deobfuscation, Options};

pub struct SymbolicUi {
    pub historical: Option<serde_json::Value>,
    pub options: Options,
    pub data: Option<Arc<Deobfuscation>>,
    pub key: Option<SymbolicKey>,
    pub loading: Option<SymbolicKey>,
    pub cancel: Arc<AtomicBool>,
    pub error: Option<String>,
    category: usize,
    offset: usize,
    inputs: String,
    request_id: u64,
}
impl Default for SymbolicUi {
    fn default() -> Self {
        Self {
            historical: None,
            options: Options::default(),
            data: None,
            key: None,
            loading: None,
            cancel: Arc::new(AtomicBool::new(false)),
            error: None,
            category: 0,
            offset: 0,
            inputs: "{}".into(),
            request_id: 0,
        }
    }
}
impl Drop for SymbolicUi {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
    }
}
impl SymbolicUi {
    pub(crate) fn begin(&mut self, context: DecompKey) -> SymbolicKey {
        self.clear();
        self.request_id = self.request_id.wrapping_add(1);
        self.cancel = Arc::new(AtomicBool::new(false));
        let key = (context.0, context.1, context.2, self.request_id);
        self.loading = Some(key);
        key
    }
    pub fn restore_options(&mut self, options: Options) {
        if options.validate().is_err() {
            return;
        }
        self.clear();
        self.inputs =
            serde_json::to_string(&options.concrete_inputs).unwrap_or_else(|_| "{}".into());
        self.options = options;
    }
    pub fn clear(&mut self) {
        self.cancel.store(true, Ordering::Release);
        self.data = None;
        self.key = None;
        self.loading = None;
        self.error = None;
    }
}
pub(crate) struct SymbolicTask {
    pub binary: Arc<ura_core::LoadedBinary>,
    pub analysis: Arc<ura_core::ProgramAnalysis>,
    pub key: SymbolicKey,
    pub context: ura_core::decomp::DecompContext,
    pub options: Options,
}
impl SymbolicTask {
    pub fn run(
        self,
        backend: &dyn symbolic::solver::Backend,
        control: &dyn ura_core::AnalysisControl,
    ) -> Result<Event, String> {
        let data = symbolic::deobfuscate(
            &self.binary,
            &self.analysis,
            self.key.2,
            &self.context,
            &self.options,
            backend,
            control,
        )?;
        if serde_json::to_vec(&data).map_err(|e| e.to_string())?.len() > 24 * 1024 * 1024 {
            return Err("Symbolic result exceeds 24MiB; reduce bounds/function size".into());
        }
        Ok(Event::Symbolic {
            key: self.key,
            data: Arc::new(data),
        })
    }
}
impl Workspace {
    pub fn symbolic_view(&mut self, ui: &mut egui::Ui) {
        let Some(function) = self.function().map(|f| f.address) else {
            ui.label("Select an analyzed function.");
            return;
        };
        let key = (self.analysis_revision, self.project_revision, function);
        if self
            .symbolic
            .key
            .is_some_and(|old| (old.0, old.1, old.2) != key)
            || self
                .symbolic
                .loading
                .is_some_and(|old| (old.0, old.1, old.2) != key)
        {
            self.symbolic.clear();
        }
        ui.label(format!(
            "Function {} · static symbolic analysis",
            ura_core::format_address(function)
        ));
        ui.label("Proofs apply to verified scalar IR. Original instructions and pseudocode remain available.");
        ui.add_enabled_ui(self.symbolic.loading.is_none(), |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.add(
                    egui::DragValue::new(&mut self.symbolic.options.max_paths)
                        .range(1..=256)
                        .prefix("Paths "),
                );
                ui.add(
                    egui::DragValue::new(&mut self.symbolic.options.solver.timeout_ms)
                        .range(1..=10_000)
                        .suffix(" ms / solver query"),
                );
                ui.add(
                    egui::DragValue::new(&mut self.symbolic.options.total_ms)
                        .range(1..=120_000)
                        .suffix(" ms total"),
                );
                ui.add(
                    egui::DragValue::new(&mut self.symbolic.options.max_depth)
                        .range(1..=256)
                        .prefix("Depth "),
                );
            });
            ui.horizontal_wrapped(|ui| {
                ui.checkbox(&mut self.symbolic.options.prove_predicates, "Branch proofs");
                ui.checkbox(&mut self.symbolic.options.explore_paths, "Paths");
                ui.checkbox(
                    &mut self.symbolic.options.recover_dispatchers,
                    "Dispatcher transitions",
                );
                ui.checkbox(
                    &mut self.symbolic.options.recover_indirect_targets,
                    "Indirect targets",
                );
            });
            ui.horizontal(|ui| {
                ui.label("Concrete entry registers (JSON; others symbolic)");
                ui.text_edit_singleline(&mut self.symbolic.inputs);
            });
        });
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    self.symbolic.loading.is_none() && !self.opening && !self.analyzing,
                    egui::Button::new("Analyze function"),
                )
                .clicked()
            {
                let inputs = serde_json::from_str(&self.symbolic.inputs);
                match inputs {
                    Err(error) => {
                        self.symbolic.error = Some(format!("Invalid input registers: {error}"))
                    }
                    Ok(inputs) => {
                        self.symbolic.options.concrete_inputs = inputs;
                        if let Err(error) = self.symbolic.options.validate() {
                            self.symbolic.error = Some(error);
                        } else if let (Some(binary), Some(analysis)) =
                            (self.binary.clone(), self.analysis.clone())
                        {
                            let key = self.symbolic.begin(key);
                            let control = Control {
                                cancel: self.symbolic.cancel.clone(),
                                progress: self.progress.clone(),
                                ctx: self.ctx.clone(),
                                last: Mutex::new(Instant::now()),
                            };
                            let context = self.decomp_context(function);
                            let options = self.symbolic.options.clone();
                            let task = SymbolicTask {
                                binary,
                                analysis,
                                key,
                                context,
                                options,
                            };
                            self.symbolic.loading = Some(key);
                            self.worker.submit_typed(
                                self.generation,
                                TaskKind::Symbolic(key),
                                move || task.run(&symbolic::solver::IsolatedZ3, &control),
                            );
                        }
                    }
                }
            }
            if self.symbolic.loading.is_some() {
                ui.spinner();
                if ui.button("Cancel").clicked() {
                    self.symbolic.cancel.store(true, Ordering::Release);
                }
            }
        });
        if let Some(error) = &self.symbolic.error {
            ui.colored_label(egui::Color32::LIGHT_RED, error);
        }
        let Some(data) = self.symbolic.data.clone() else {
            if let Some(history) = self.symbolic.historical.clone() {
                ui.collapsing(
                    "Saved findings · historical only; reanalysis required",
                    |ui| {
                        if ui.button("Load saved configuration").clicked()
                            && let Ok(options) = serde_json::from_value(history["options"].clone())
                        {
                            self.symbolic.restore_options(options);
                        }
                        let mut text = serde_json::to_string_pretty(&history).unwrap_or_default();
                        if text.len() > 65536 {
                            text.truncate(text.floor_char_boundary(65536));
                            text.push_str("\n… historical metadata truncated in this view");
                        }
                        egui::ScrollArea::both().show(ui, |ui| {
                            ui.add(
                                egui::TextEdit::multiline(&mut text)
                                    .code_editor()
                                    .interactive(false),
                            );
                        });
                    },
                );
            }
            return;
        };
        let report = &data.report;
        ui.label(format!(
            "{} · {} predicates · {} validated edge removals · {} paths · {} queries · {:.1} ms",
            report.solver,
            report.predicates.len(),
            report.removed_edges.len(),
            report.paths.len(),
            report.queries.len(),
            report.elapsed_us as f64 / 1000.0
        ));
        if !report.complete {
            ui.label("Exploration incomplete. Path results do not establish unrestricted whole-function coverage.");
        }
        for note in &report.diagnostics {
            ui.label(note);
        }
        ui.horizontal_wrapped(|ui| {
            for (index, title) in [
                "Predicates",
                "Paths",
                "Proofs / models",
                "Dispatchers",
                "Indirect targets",
                "Derived edges",
                "Pseudocode",
                "Value sets",
            ]
            .iter()
            .enumerate()
            {
                if ui
                    .selectable_label(self.symbolic.category == index, *title)
                    .clicked()
                {
                    self.symbolic.category = index;
                    self.symbolic.offset = 0;
                }
            }
        });
        if self.symbolic.category == 6 {
            ui.columns(2, |columns| {
                for (column, (title, source)) in columns.iter_mut().zip([
                    ("Original", &data.original.pseudocode),
                    (
                        "Derived · validated branch pruning",
                        &data.simplified.pseudocode,
                    ),
                ]) {
                    column.label(title);
                    let row_height = column
                        .text_style_height(&egui::TextStyle::Monospace)
                        .max(18.0);
                    egui::ScrollArea::both().id_salt(title).show_rows(
                        column,
                        row_height,
                        source.lines.len(),
                        |ui, range| {
                            for line in &source.lines[range] {
                                ui.monospace(format!(
                                    "{:5} {}{}",
                                    line.number,
                                    "    ".repeat(line.indent),
                                    line.text
                                ));
                            }
                        },
                    );
                }
            });
            return;
        }
        let offset = self.symbolic.offset;
        fn page<T: serde::Serialize>(values: &[T], offset: usize) -> (usize, String) {
            let end = offset.saturating_add(16).min(values.len());
            let start = offset.min(end);
            (
                values.len(),
                serde_json::to_string_pretty(&values[start..end]).unwrap_or_else(|e| e.to_string()),
            )
        }
        let (count, mut text) = match self.symbolic.category {
            0 => page(&report.predicates, offset),
            1 => page(&report.paths, offset),
            2 => page(&report.queries, offset),
            3 => page(&report.dispatchers, offset),
            4 => page(&report.indirect_targets, offset),
            5 => page(&report.removed_edges, offset),
            _ => page(&data.value_sets.facts, offset),
        };
        ui.horizontal(|ui| {
            ui.label(format!("{} records · page starts at {}", count, offset));
            if ui
                .add_enabled(offset > 0, egui::Button::new("Previous"))
                .clicked()
            {
                self.symbolic.offset = offset.saturating_sub(16);
            }
            if ui
                .add_enabled(offset.saturating_add(16) < count, egui::Button::new("Next"))
                .clicked()
            {
                self.symbolic.offset = offset + 16;
            }
        });
        // Pages remain bounded even when one path contains a large trace.
        if text.len() > 256 * 1024 {
            text.truncate(text.floor_char_boundary(256 * 1024));
            text.push_str("\n… use CLI/MCP pages or export for full evidence");
        }
        egui::ScrollArea::both().show(ui, |ui| {
            ui.add(
                egui::TextEdit::multiline(&mut text)
                    .code_editor()
                    .desired_width(f32::INFINITY)
                    .interactive(false),
            );
        });
    }
}
