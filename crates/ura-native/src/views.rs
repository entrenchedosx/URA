use crate::{app::*, navigation::Location};
use eframe::egui::{self, Align2, Color32, FontId, Key, RichText, Sense};
use egui_extras::{Column, TableBuilder};
use ura_core::{format_address, parse_address};

impl egui_dock::TabViewer for Workspace {
    type Tab = Panel;
    fn id(&mut self, tab: &mut Panel) -> egui::Id {
        egui::Id::new(*tab)
    }
    fn title(&mut self, tab: &mut Panel) -> egui::WidgetText {
        tab.title().into()
    }
    fn ui(&mut self, ui: &mut egui::Ui, tab: &mut Panel) {
        if ui.rect_contains_pointer(ui.max_rect()) && ui.input(|i| i.pointer.any_pressed()) {
            self.active = *tab;
        }
        ui.style_mut().text_styles.insert(
            egui::TextStyle::Monospace,
            FontId::monospace(self.settings.font_size),
        );
        match tab {
            Panel::Explorer => self.explorer(ui),
            Panel::Disassembly => self.disassembly(ui),
            Panel::Functions => self.functions(ui),
            Panel::Graph => self.graph_view(ui),
            Panel::Hex => self.hex(ui),
            Panel::Strings => self.strings_view(ui),
            Panel::Xrefs => self.xrefs(ui),
            Panel::Overview => self.overview(ui),
            Panel::Inspector => self.inspector(ui),
            Panel::Messages => self.messages_view(ui),
            Panel::GraphOverview => self.graph_overview(ui),
            Panel::Ir => self.ir_view(ui),
            Panel::Signature => self.signature_view(ui),
            Panel::Stack => self.stack_view(ui),
            Panel::Types => self.types_view(ui),
            Panel::CallGraph => self.call_graph_view(ui),
            Panel::HighLevel => self.high_level_view(ui),
        }
    }
    fn scroll_bars(&self, _tab: &Panel) -> [bool; 2] {
        [false, false]
    }
    fn on_tab_button(&mut self, tab: &mut Panel, response: &egui::Response) {
        if response.clicked() {
            self.active = *tab;
        }
    }
    fn context_menu(&mut self, ui: &mut egui::Ui, _tab: &mut Panel, _path: egui_dock::NodePath) {
        if ui.button("Reset workspace layout").clicked() {
            self.actions.push(Action::ResetLayout);
            ui.close();
        }
        ui.menu_button("Restore panel", |ui| {
            for p in Panel::ALL {
                if ui.button(p.title()).clicked() {
                    self.actions.push(Action::Show(p));
                    ui.close();
                }
            }
        });
    }
}

impl Workspace {
    fn ir_view(&mut self, ui: &mut egui::Ui) {
        let Some(function) = self.function().map(|f| (f.address, self.name(f))) else {
            ui.label("Select an analyzed function to inspect IR.");
            return;
        };
        ui.horizontal(|ui| {
            ui.label(RichText::new(function.1).strong());
            ui.selectable_value(&mut self.ir_ssa, false, "Raw IR");
            ui.selectable_value(&mut self.ir_ssa, true, "SSA IR");
        });
        self.ensure_ir();
        if let Some(error) = &self.ir_error {
            ui.colored_label(self.colors().error, error);
            if ui.button("Retry IR analysis").clicked() {
                self.ir_key = None;
                self.ir_error = None;
                self.cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            }
            return;
        }
        if self.ir_key != Some((self.analysis_revision, function.0, self.ir_ssa)) {
            ui.label("Lifting and verifying function…");
            return;
        }
        if let Some(bundle) = &self.ir_bundle {
            ui.label(format!(
                "{} blocks · {} source instructions · {} unsupported instructions · IR schema {}",
                bundle.raw.blocks.len(),
                bundle.raw.source_instructions,
                bundle.raw.diagnostics.len(),
                bundle.raw.ir_version
            ));
        }
        ui.separator();
        let colors = self.colors();
        let mut navigate = None;
        egui::ScrollArea::both()
            .id_salt(("ir-rows", function.0, self.ir_ssa))
            .show_rows(
                ui,
                self.settings.row_height,
                self.ir_rows.len(),
                |ui, range| {
                    for i in range {
                        let row = &self.ir_rows[i];
                        ui.horizontal(|ui| {
                            if ui
                                .selectable_label(
                                    self.location.address == Some(row.source),
                                    RichText::new(format_address(row.source))
                                        .monospace()
                                        .color(colors.accent),
                                )
                                .on_hover_text("Navigate to source instruction")
                                .clicked()
                            {
                                navigate = Some(row.source);
                            }
                            let color = if row.unsupported {
                                colors.error
                            } else if row.block {
                                colors.branch
                            } else {
                                colors.text
                            };
                            let mut job = egui::text::LayoutJob::default();
                            for word in row.text.split_inclusive(|c: char| {
                                c.is_whitespace() || c == ',' || c == '(' || c == ')'
                            }) {
                                let token_color =
                                    if word.contains(':') && !row.block && !row.unsupported {
                                        colors.register
                                    } else if word.starts_with("0x") {
                                        colors.gold
                                    } else {
                                        color
                                    };
                                job.append(
                                    word,
                                    0.0,
                                    egui::TextFormat {
                                        font_id: FontId::monospace(self.settings.font_size),
                                        color: token_color,
                                        ..Default::default()
                                    },
                                );
                            }
                            job.wrap.max_width = f32::INFINITY;
                            ui.add(egui::Label::new(job).wrap_mode(egui::TextWrapMode::Extend));
                        });
                    }
                },
            );
        if let Some(address) = navigate {
            self.navigate_address(address);
        }
    }
    pub fn status(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if self.opening {
                ui.spinner();
                ui.label("Opening image…");
            } else if self.analyzing {
                ui.spinner();
                if let Some(progress) = self
                    .progress
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .as_ref()
                {
                    ui.label(format!(
                        "{:?} · {} instructions · {} functions",
                        progress.stage, progress.instructions, progress.functions
                    ));
                } else {
                    ui.label("Preparing analysis…");
                }
            } else if self.ir_loading.is_some() {
                ui.label("Analyzing IR…");
            } else {
                ui.colored_label(self.colors().accent, "●");
                ui.label("Ready");
            }
            ui.separator();
            if let Some(address) = self.location.address {
                ui.label(mono(format_address(address)));
            }
            if let Some(offset) = self.location.file_offset {
                ui.label(RichText::new(format!("file {offset:#x}")).color(self.colors().muted));
            }
            if let Some(analysis) = &self.analysis {
                ui.separator();
                ui.label(format!(
                    "{} functions · {} xrefs",
                    analysis.functions.len(),
                    analysis.xrefs.len()
                ));
                if analysis.report.cancelled || analysis.report.truncated {
                    ui.colored_label(self.colors().gold, "Partial analysis");
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if let Some(info) = &self.info {
                    ui.label(&info.architecture);
                }
                if let Some((_, project)) = &self.project {
                    ui.label(&project.project.name);
                }
                if let Some((_, p)) = &self.project {
                    ui.colored_label(
                        if p.binary_status == "unchanged" {
                            self.colors().muted
                        } else {
                            self.colors().gold
                        },
                        format!("Project: {}", p.binary_status),
                    );
                }
            });
        });
    }
    fn decomp_target(&mut self, ui: &mut egui::Ui, description: &str) -> Option<(u64, String)> {
        if self.analysis.is_none() {
            ui.label(format!(
                "Analyze a binary to inspect the recovered {description}."
            ));
            return None;
        }
        let Some(function) = self.function() else {
            ui.label(format!(
                "Select an analyzed function to inspect its recovered {description}."
            ));
            return None;
        };
        Some((function.address, self.name(function)))
    }
    fn decomp_data(
        &mut self,
        ui: &mut egui::Ui,
        function: u64,
    ) -> Option<std::sync::Arc<ura_core::decomp::FunctionDecompilation>> {
        self.ensure_decomp();
        let key = (self.analysis_revision, self.project_revision, function);
        if self.decomp_key == Some(key)
            && let Some(data) = &self.decomp
            && data.function == function
        {
            return Some(data.clone());
        }
        if self.decomp_key == Some(key)
            && let Some(error) = &self.decomp_error
        {
            ui.colored_label(self.colors().error, error);
            if ui.button("Retry decompilation").clicked() {
                self.decomp_key = None;
                self.decomp_error = None;
            }
            return None;
        }
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label("Recovering signature, stack frame, types and high-level IR…");
        });
        None
    }
    fn call_graph_data(
        &mut self,
        ui: &mut egui::Ui,
    ) -> Option<std::sync::Arc<ura_core::decomp::CallGraph>> {
        self.ensure_call_graph();
        if let Some(error) = &self.call_graph_error {
            ui.colored_label(self.colors().error, error);
            if ui.button("Retry call graph").clicked() {
                self.call_graph_key = None;
                self.call_graph_error = None;
            }
            return None;
        }
        if self.call_graph_key != Some(self.analysis_revision) {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Building call graph…");
            });
            return None;
        }
        self.call_graph.clone()
    }
    fn signature_view(&mut self, ui: &mut egui::Ui) {
        let Some((function, name)) = self.decomp_target(ui, "function signature") else {
            return;
        };
        let Some(data) = self.decomp_data(ui, function) else {
            return;
        };
        ui.horizontal(|ui| {
            ui.label(RichText::new(name).strong());
            ui.label(
                RichText::new(format_address(function))
                    .monospace()
                    .color(self.colors().muted),
            );
            ui.separator();
            ui.label(
                RichText::new("Recovered, not original source")
                    .small()
                    .color(self.colors().muted),
            );
        });
        let signature = &data.signature;
        ui.horizontal(|ui| {
            if ui
                .add_enabled(self.project.is_some(), egui::Button::new("Edit signature…"))
                .clicked()
            {
                self.edit_signature(&data);
            }
            if self.project.is_none() {
                ui.small("Create or open a project to save signatures.");
            }
        });
        ui.add_space(4.0);
        ui.label(
            RichText::new(signature.declaration())
                .monospace()
                .size(self.settings.font_size + 1.0),
        );
        ui.add_space(4.0);
        egui::Grid::new(("signature-meta", function))
            .num_columns(2)
            .spacing([18.0, 3.0])
            .show(ui, |ui| {
                ui.label("Convention");
                ui.label(format!(
                    "{} ({})",
                    signature.convention.name(),
                    signature.convention_confidence.name()
                ));
                ui.end_row();
                ui.label("Return");
                ui.label(format!(
                    "{} ({})",
                    signature.return_value.ty.display(),
                    signature.return_value.confidence.name()
                ));
                ui.end_row();
                ui.label("Parameters");
                ui.label(format!(
                    "{} recovered · {} stack bytes",
                    signature.parameter_count(),
                    signature.stack_parameter_bytes
                ));
                ui.end_row();
                ui.label("Override");
                ui.label(if signature.user_override {
                    "user-authored signature applied"
                } else {
                    "none · inference only"
                });
                ui.end_row();
            });
        ui.separator();
        if signature.parameters.is_empty() {
            ui.label("No parameters were observed in the verified IR.");
        } else {
            egui::ScrollArea::both()
                .id_salt(("signature-parameters", function))
                .max_height(ui.available_height() * 0.55)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    egui::Grid::new(("signature-parameters-grid", function))
                        .num_columns(6)
                        .striped(true)
                        .spacing([14.0, 3.0])
                        .show(ui, |ui| {
                            for header in ["#", "Name", "Location", "Type", "Uses", "Confidence"] {
                                ui.label(RichText::new(header).strong());
                            }
                            ui.end_row();
                            for parameter in &signature.parameters {
                                ui.label(parameter.index.to_string());
                                ui.label(
                                    RichText::new(if parameter.name.is_empty() {
                                        format!("a{}", parameter.index)
                                    } else {
                                        parameter.name.clone()
                                    })
                                    .monospace(),
                                );
                                ui.label(parameter.location.display());
                                ui.label(parameter.ty.display());
                                ui.label(parameter.uses.to_string());
                                ui.label(parameter.confidence.name());
                                ui.end_row();
                            }
                        });
                });
        }
        if !signature.conflicts.is_empty() {
            ui.separator();
            for conflict in &signature.conflicts {
                ui.colored_label(self.colors().gold, format!("Conflict: {conflict}"));
            }
        }
        if !data.diagnostics.is_empty() {
            ui.separator();
            egui::CollapsingHeader::new(format!("Diagnostics ({})", data.diagnostics.len()))
                .id_salt(("signature-diagnostics", function))
                .show(ui, |ui| {
                    for note in &data.diagnostics {
                        ui.label(note);
                    }
                });
        }
        if !signature.evidence.is_empty() {
            egui::CollapsingHeader::new(format!("Evidence ({})", signature.evidence.len()))
                .id_salt(("signature-evidence", function))
                .show(ui, |ui| {
                    let mut navigate = None;
                    for evidence in &signature.evidence {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(&evidence.kind).strong());
                            match evidence.address {
                                Some(address) => {
                                    if ui
                                        .selectable_label(
                                            false,
                                            RichText::new(format_address(address))
                                                .monospace()
                                                .color(self.colors().accent),
                                        )
                                        .clicked()
                                    {
                                        navigate = Some(address);
                                    }
                                }
                                None => {
                                    ui.label("-");
                                }
                            }
                            ui.label(&evidence.detail);
                        });
                    }
                    if let Some(address) = navigate {
                        self.navigate_address(address);
                    }
                });
        }
    }
    fn stack_view(&mut self, ui: &mut egui::Ui) {
        let Some((function, name)) = self.decomp_target(ui, "stack frame") else {
            return;
        };
        let Some(data) = self.decomp_data(ui, function) else {
            return;
        };
        let frame = &data.frame;
        ui.horizontal(|ui| {
            ui.label(RichText::new(name).strong());
            ui.label(
                RichText::new(format_address(function))
                    .monospace()
                    .color(self.colors().muted),
            );
        });
        ui.label(format!(
            "frame {} bytes · locals {} · incoming arguments {} · alignment {} · frame pointer {}",
            frame.frame_size,
            frame.local_bytes,
            frame.incoming_argument_bytes,
            frame.alignment,
            frame.uses_frame_pointer
        ));
        ui.label(format!(
            "return address at {:+} · saved registers: {} · {} slots{}",
            frame.return_address_offset,
            if frame.saved_registers.is_empty() {
                "none".to_string()
            } else {
                frame.saved_registers.join(", ")
            },
            frame.slots.len(),
            if frame.truncated { " · truncated" } else { "" }
        ));
        ui.small("Double-click a name to edit; right-click for all instruction references.");
        ui.separator();
        let mut navigate = None;
        egui::ScrollArea::both()
            .id_salt(("stack-slots", function))
            .auto_shrink([false, false])
            .show(ui, |ui| {
                egui::Grid::new(("stack-slots-grid", function))
                    .num_columns(8)
                    .striped(true)
                    .spacing([14.0, 3.0])
                    .show(ui, |ui| {
                        for header in [
                            "Offset",
                            "Name",
                            "Kind",
                            "Type",
                            "R/W",
                            "Lifetime",
                            "Saved",
                            "Confidence",
                        ] {
                            ui.label(RichText::new(header).strong());
                        }
                        ui.end_row();
                        for slot in &frame.slots {
                            ui.label(format!("{:+}", slot.offset));
                            let response = ui.selectable_label(
                                false,
                                RichText::new(slot.user_name.as_deref().unwrap_or(&slot.name))
                                    .monospace(),
                            );
                            response.context_menu(|ui| {
                                if ui
                                    .add_enabled(
                                        self.project.is_some(),
                                        egui::Button::new("Edit name / type…"),
                                    )
                                    .clicked()
                                {
                                    self.edit_stack_slot(function, slot);
                                    ui.close();
                                }
                                ui.separator();
                                for access in &slot.accesses {
                                    if ui
                                        .button(format!(
                                            "{}  {}{}  {}",
                                            format_address(access.instruction),
                                            if access.read { "R" } else { "" },
                                            if access.write { "W" } else { "" },
                                            access.mnemonic
                                        ))
                                        .clicked()
                                    {
                                        navigate = Some(access.instruction);
                                        ui.close();
                                    }
                                }
                            });
                            if response.double_clicked() && self.project.is_some() {
                                self.edit_stack_slot(function, slot);
                            }
                            ui.label(&slot.kind);
                            ui.label(slot.user_type.as_ref().unwrap_or(&slot.ty).display());
                            ui.label(format!("{}/{}", slot.reads, slot.writes));
                            ui.horizontal(|ui| {
                                if ui
                                    .selectable_label(
                                        false,
                                        RichText::new(format_address(slot.first_instruction))
                                            .monospace()
                                            .color(self.colors().accent),
                                    )
                                    .clicked()
                                {
                                    navigate = Some(slot.first_instruction);
                                }
                                ui.label("..");
                                ui.label(
                                    RichText::new(format_address(slot.last_instruction))
                                        .monospace()
                                        .color(self.colors().muted),
                                );
                            });
                            ui.label(slot.saved_register.as_deref().unwrap_or("-"));
                            ui.label(slot.confidence.name());
                            ui.end_row();
                        }
                    });
            });
        if let Some(address) = navigate {
            self.navigate_address(address);
        }
        if !frame.notes.is_empty() {
            ui.separator();
            for note in &frame.notes {
                ui.colored_label(self.colors().muted, note);
            }
        }
        if !data.diagnostics.is_empty() {
            egui::CollapsingHeader::new(format!("Diagnostics ({})", data.diagnostics.len()))
                .id_salt(("stack-diagnostics", function))
                .show(ui, |ui| {
                    for note in &data.diagnostics {
                        ui.label(note);
                    }
                });
        }
    }
    fn types_view(&mut self, ui: &mut egui::Ui) {
        let library = self.project.as_ref().and_then(|p| p.1.type_library.clone());
        ui.horizontal(|ui| {
            if ui
                .add_enabled(self.project.is_some(), egui::Button::new("New structure…"))
                .clicked()
            {
                self.edit_structure(None);
            }
            if ui
                .add_enabled(self.project.is_some(), egui::Button::new("New type alias…"))
                .clicked()
            {
                self.edit_alias(None, None);
            }
        });
        if let Some(library) = library {
            egui::CollapsingHeader::new(format!(
                "Project types ({})",
                library.structures.len() + library.typedefs.len()
            ))
            .default_open(true)
            .show(ui, |ui| {
                for structure in library.structures.values() {
                    if ui
                        .button(format!(
                            "{} {} · {} fields",
                            if structure.union { "union" } else { "struct" },
                            structure.name,
                            structure.fields.len()
                        ))
                        .clicked()
                    {
                        self.edit_structure(Some(structure));
                    }
                }
                for (name, ty) in &library.typedefs {
                    if ui.button(format!("{name} = {}", ty.display())).clicked() {
                        self.edit_alias(Some(name), Some(ty));
                    }
                }
            });
        }
        ui.separator();
        let Some((function, name)) = self.decomp_target(ui, "types") else {
            return;
        };
        let Some(data) = self.decomp_data(ui, function) else {
            return;
        };
        let inference = &data.types;
        ui.horizontal(|ui| {
            ui.label(RichText::new(name).strong());
            ui.label(
                RichText::new(format_address(function))
                    .monospace()
                    .color(self.colors().muted),
            );
        });
        ui.label(format!(
            "{} variables · {} conflicts{} · conservative constraints only",
            inference.variables.len(),
            inference.conflicts,
            if inference.truncated {
                " · truncated"
            } else {
                ""
            }
        ));
        ui.separator();
        egui::ScrollArea::vertical()
            .id_salt(("types-variables", function))
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for variable in &inference.variables {
                    egui::CollapsingHeader::new(format!(
                        "{} : {}  ·  {}",
                        variable.variable,
                        variable.ty.display(),
                        variable.confidence.name()
                    ))
                    .id_salt(("type-variable", function, variable.variable_id))
                    .show(ui, |ui| {
                        if variable.constraints.is_empty() {
                            ui.label("No constraints recorded.");
                        }
                        for constraint in &variable.constraints {
                            ui.label(format!(
                                "{} at {}{}",
                                constraint.kind,
                                constraint
                                    .source
                                    .map(format_address)
                                    .unwrap_or_else(|| "-".into()),
                                if constraint.detail.is_empty() {
                                    String::new()
                                } else {
                                    format!(" · {}", constraint.detail)
                                }
                            ));
                        }
                        for conflict in &variable.conflicts {
                            ui.colored_label(self.colors().gold, format!("Conflict: {conflict}"));
                        }
                    });
                }
            });
        if !inference.notes.is_empty() {
            ui.separator();
            for note in &inference.notes {
                ui.colored_label(self.colors().muted, note);
            }
        }
    }
    fn high_level_view(&mut self, ui: &mut egui::Ui) {
        let Some((function, name)) = self.decomp_target(ui, "high-level IR") else {
            return;
        };
        let Some(data) = self.decomp_data(ui, function) else {
            return;
        };
        let high_level = &data.high_level;
        ui.horizontal(|ui| {
            ui.label(RichText::new(name).strong());
            ui.label(
                RichText::new(format_address(function))
                    .monospace()
                    .color(self.colors().muted),
            );
            ui.separator();
            ui.label(high_level.syntax.clone());
            ui.colored_label(self.colors().gold, high_level.status.clone());
            if ui.button("Copy").clicked() {
                ui.ctx().copy_text(high_level.text());
            }
        });
        ui.label(
            RichText::new(
                "Structural rendering of verified SSA. It is not source code and is not claimed to compile.",
            )
            .small()
            .color(self.colors().muted),
        );
        if high_level.unresolved > 0 {
            ui.colored_label(
                self.colors().gold,
                format!(
                    "{} unresolved call(s) or construct(s) are marked instead of guessed",
                    high_level.unresolved
                ),
            );
        }
        ui.separator();
        let mut navigate = None;
        egui::ScrollArea::both()
            .id_salt(("high-level-lines", function))
            .auto_shrink([false, false])
            .show_rows(
                ui,
                self.settings.row_height,
                high_level.lines.len(),
                |ui, range| {
                    for line in &high_level.lines[range] {
                        ui.horizontal(|ui| {
                            match line.address {
                                Some(address) => {
                                    if ui
                                        .selectable_label(
                                            self.location.address == Some(address),
                                            RichText::new(format_address(address))
                                                .monospace()
                                                .color(self.colors().accent),
                                        )
                                        .clicked()
                                    {
                                        navigate = Some(address);
                                    }
                                }
                                None => {
                                    ui.label(
                                        RichText::new("            ")
                                            .monospace()
                                            .color(self.colors().muted),
                                    );
                                }
                            }
                            ui.label(
                                RichText::new(format!("{}{}", "  ".repeat(line.indent), line.text))
                                    .monospace(),
                            );
                        });
                    }
                },
            );
        if let Some(address) = navigate {
            self.navigate_address(address);
        }
        if !high_level.notes.is_empty() {
            ui.separator();
            for note in &high_level.notes {
                ui.colored_label(self.colors().muted, note);
            }
        }
    }
    fn call_graph_view(&mut self, ui: &mut egui::Ui) {
        if self.analysis.is_none() {
            ui.label("Analyze a binary to inspect the call graph.");
            return;
        }
        let Some(graph) = self.call_graph_data(ui) else {
            return;
        };
        ui.horizontal(|ui| {
            ui.label(RichText::new("Recovered call graph").strong());
            ui.label(format!(
                "{} nodes · {} edges · {} cycles · {} unresolved indirect",
                graph.nodes.len(),
                graph.edges.len(),
                graph.cycles.len(),
                graph.unresolved_indirect
            ));
            if graph.truncated {
                ui.colored_label(self.colors().gold, "truncated");
            }
        });
        ui.label(format!(
            "{} roots · {} leaves{}",
            graph.roots.len(),
            graph.leaves.len(),
            if graph.notes.is_empty() {
                String::new()
            } else {
                format!(" · {}", graph.notes.join(" · "))
            }
        ));
        if !graph.cycles.is_empty() {
            egui::CollapsingHeader::new(format!("Cycles ({})", graph.cycles.len()))
                .id_salt("call-graph-cycles")
                .show(ui, |ui| {
                    for cycle in &graph.cycles {
                        ui.label(
                            RichText::new(
                                cycle
                                    .iter()
                                    .map(|address| format_address(*address))
                                    .collect::<Vec<_>>()
                                    .join(" -> "),
                            )
                            .monospace(),
                        );
                    }
                });
        }
        ui.separator();
        let mut navigate = None;
        egui::ScrollArea::vertical()
            .id_salt("call-graph-nodes")
            .auto_shrink([false, false])
            .show_rows(
                ui,
                self.settings.row_height,
                graph.nodes.len(),
                |ui, range| {
                    for node in &graph.nodes[range] {
                        ui.horizontal(|ui| {
                            if ui
                                .selectable_label(
                                    self.location.address == Some(node.address),
                                    RichText::new(format_address(node.address))
                                        .monospace()
                                        .color(self.colors().accent),
                                )
                                .clicked()
                            {
                                navigate = Some(node.address);
                            }
                            ui.label(RichText::new(&node.name).strong());
                            if node.external {
                                ui.colored_label(self.colors().gold, "external");
                            }
                            if node.recursive {
                                ui.colored_label(self.colors().gold, "recursive");
                            }
                            ui.label(format!(
                                "in {} · out {}{}",
                                node.callers,
                                node.callees,
                                node.component
                                    .map(|component| format!(" · component {component}"))
                                    .unwrap_or_default()
                            ));
                        });
                    }
                },
            );
        if let Some(address) = navigate {
            self.actions
                .push(Action::Navigate(self.address_location(address), true));
        }
        egui::CollapsingHeader::new(format!("Edges ({})", graph.edges.len()))
            .id_salt("call-graph-edges")
            .show(ui, |ui| {
                for edge in &graph.edges {
                    ui.label(
                        RichText::new(format!(
                            "{} -> {} [{}]{}",
                            format_address(edge.from),
                            format_address(edge.to),
                            edge.kind,
                            edge.instruction
                                .map(|instruction| format!(" at {}", format_address(instruction)))
                                .unwrap_or_default()
                        ))
                        .monospace(),
                    );
                }
            });
    }
    fn empty(&mut self, ui: &mut egui::Ui) -> bool {
        if self.binary.is_some() {
            return false;
        }
        ui.add_space(6.0);
        ui.image((self.icon.id(), egui::vec2(96.0, 96.0)));
        if let Some((_, snapshot)) = &self.project {
            ui.colored_label(
                self.colors().gold,
                format!("Binary {}", snapshot.binary_status),
            );
            ui.label(&snapshot.project.binary_path);
        } else {
            ui.label(
                RichText::new("Open an executable image")
                    .size(18.0)
                    .strong(),
            );
            ui.label(
                RichText::new("PE · ELF · Mach-O  /  x86 and x64 disassembly")
                    .color(self.colors().muted),
            );
        }
        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            if ui.button("Open binary…    Ctrl+O").clicked() {
                self.actions.push(Action::OpenDialog(false));
            }
            if ui.button("Open project…").clicked() {
                self.actions.push(Action::OpenDialog(true));
            }
        });
        if !self.recent.is_empty() {
            ui.add_space(16.0);
            ui.label(RichText::new("RECENT").small().color(self.colors().muted));
            for p in &self.recent {
                if ui.link(p.to_string_lossy()).clicked() {
                    self.actions.push(Action::Open(p.clone()));
                }
            }
        }
        true
    }

    fn explorer(&mut self, ui: &mut egui::Ui) {
        if self.empty(ui) {
            return;
        }
        ui.horizontal_wrapped(|ui| {
            for (i, title) in ["Sections", "Symbols", "Imports", "Exports"]
                .iter()
                .enumerate()
            {
                if ui
                    .selectable_value(&mut self.explorer_mode, i, *title)
                    .changed()
                {
                    self.explorer_filter.dirty = true;
                }
            }
        });
        if ui
            .add(
                egui::TextEdit::singleline(&mut self.explorer_filter.query)
                    .hint_text("Filter explorer…")
                    .desired_width(f32::INFINITY),
            )
            .changed()
        {
            self.explorer_filter.dirty = true;
        }
        let binary = self.binary.clone().unwrap();
        let a = binary.analysis();
        if self.explorer_filter.dirty {
            let q = self.explorer_filter.query.to_lowercase();
            self.explorer_filter.indices = match self.explorer_mode {
                0 => a
                    .sections
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| s.name.to_lowercase().contains(&q))
                    .map(|(i, _)| i)
                    .collect(),
                1 => a
                    .symbols
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| s.name.to_lowercase().contains(&q))
                    .map(|(i, _)| i)
                    .collect(),
                2 => a
                    .imports
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| {
                        s.name.to_lowercase().contains(&q)
                            || s.library
                                .as_deref()
                                .unwrap_or("")
                                .to_lowercase()
                                .contains(&q)
                    })
                    .map(|(i, _)| i)
                    .collect(),
                _ => a
                    .exports
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| s.name.to_lowercase().contains(&q))
                    .map(|(i, _)| i)
                    .collect(),
            };
            self.explorer_filter.dirty = false;
        }
        ui.label(
            RichText::new(format!("{} entries", self.explorer_filter.indices.len()))
                .small()
                .color(self.colors().muted),
        );
        egui::ScrollArea::both()
            .id_salt("explorer-scroll")
            .show_rows(
                ui,
                self.settings.row_height,
                self.explorer_filter.indices.len(),
                |ui, range| {
                    for row in range {
                        let i = self.explorer_filter.indices[row];
                        let (label, detail, address) = match self.explorer_mode {
                            0 => {
                                let s = &a.sections[i];
                                (
                                    s.name.clone(),
                                    format!(
                                        "{}   {:#x}   {} bytes",
                                        s.permissions(),
                                        s.address,
                                        s.file_size
                                    ),
                                    Some(s.address),
                                )
                            }
                            1 => {
                                let s = &a.symbols[i];
                                (
                                    s.name.clone(),
                                    format!(
                                        "{} · {}",
                                        s.kind,
                                        s.address
                                            .map(format_address)
                                            .unwrap_or_else(|| "unmapped".into())
                                    ),
                                    s.address,
                                )
                            }
                            2 => {
                                let s = &a.imports[i];
                                (
                                    s.name.clone(),
                                    s.library
                                        .clone()
                                        .unwrap_or_else(|| "library unspecified".into()),
                                    None,
                                )
                            }
                            _ => {
                                let s = &a.exports[i];
                                (s.name.clone(), format_address(s.address), Some(s.address))
                            }
                        };
                        let response = ui
                            .add(
                                egui::Button::selectable(
                                    address.is_some() && address == self.location.address,
                                    mono(label),
                                )
                                .frame(false),
                            )
                            .on_hover_text(detail);
                        if response.clicked()
                            && let Some(address) = address
                        {
                            self.navigate_address(address);
                        }
                        response.context_menu(|ui| {
                            if ui.button("Copy name").clicked() {
                                let name = match self.explorer_mode {
                                    0 => &a.sections[i].name,
                                    1 => &a.symbols[i].name,
                                    2 => &a.imports[i].name,
                                    _ => &a.exports[i].name,
                                };
                                ui.ctx().copy_text(name.clone());
                                ui.close();
                            }
                            if let Some(address) = address {
                                self.address_menu(ui, address);
                            }
                        });
                    }
                },
            );
    }
    fn functions(&mut self, ui: &mut egui::Ui) {
        if self.empty(ui) {
            return;
        }
        let Some(analysis) = self.analysis.clone() else {
            ui.label("Run analysis to discover functions.");
            return;
        };
        if ui
            .add(
                egui::TextEdit::singleline(&mut self.function_filter.query)
                    .hint_text("Filter names, addresses or origin…")
                    .desired_width(f32::INFINITY),
            )
            .changed()
        {
            self.function_filter.dirty = true;
        }
        ui.horizontal(|ui| {
            egui::ComboBox::from_id_salt("function-sort")
                .selected_text(
                    ["Address", "Name", "Instructions", "Blocks", "References"]
                        [self.function_filter.sort.min(4)],
                )
                .width(90.0)
                .show_ui(ui, |ui| {
                    for (i, name) in ["Address", "Name", "Instructions", "Blocks", "References"]
                        .iter()
                        .enumerate()
                    {
                        if ui
                            .selectable_value(&mut self.function_filter.sort, i, *name)
                            .changed()
                        {
                            self.function_filter.dirty = true;
                        }
                    }
                });
            if ui
                .checkbox(&mut self.function_filter.descending, "Reverse")
                .changed()
            {
                self.function_filter.dirty = true;
            }
        });
        if self.function_filter.dirty {
            let q = self.function_filter.query.to_lowercase();
            self.function_filter.indices = analysis
                .functions
                .iter()
                .enumerate()
                .filter(|(_, f)| {
                    self.name(f).to_lowercase().contains(&q)
                        || format_address(f.address).to_lowercase().contains(&q)
                        || f.origin.name().to_lowercase().contains(&q)
                })
                .map(|(i, _)| i)
                .collect();
            let names = &self.names;
            let sort = self.function_filter.sort;
            self.function_filter.indices.sort_by(|&i, &j| {
                let a = &analysis.functions[i];
                let b = &analysis.functions[j];
                let cmp = match sort {
                    1 => names
                        .get(&a.address)
                        .cloned()
                        .or_else(|| a.symbol.clone())
                        .unwrap_or_else(|| a.fallback_name())
                        .to_lowercase()
                        .cmp(
                            &names
                                .get(&b.address)
                                .cloned()
                                .or_else(|| b.symbol.clone())
                                .unwrap_or_else(|| b.fallback_name())
                                .to_lowercase(),
                        ),
                    2 => a.instruction_count.cmp(&b.instruction_count),
                    3 => a.blocks.len().cmp(&b.blocks.len()),
                    4 => a.reference_count.cmp(&b.reference_count),
                    _ => a.address.cmp(&b.address),
                };
                cmp.then(a.address.cmp(&b.address))
            });
            if self.function_filter.descending {
                self.function_filter.indices.reverse();
            }
            self.function_filter.dirty = false;
        }
        ui.label(
            RichText::new(format!(
                "{} / {} functions",
                self.function_filter.indices.len(),
                analysis.functions.len()
            ))
            .small()
            .color(self.colors().muted),
        );
        let selected = self.function().map(|f| f.address);
        if ui.available_width() < 440.0 {
            let mut jump = None;
            egui::ScrollArea::both()
                .id_salt("function-browser")
                .show_rows(
                    ui,
                    self.settings.row_height,
                    self.function_filter.indices.len(),
                    |ui, range| {
                        for row in range {
                            let f = &analysis.functions[self.function_filter.indices[row]];
                            ui.horizontal(|ui| {
                                ui.colored_label(self.colors().accent, "ƒ");
                                let response = ui
                                    .selectable_label(
                                        selected == Some(f.address),
                                        mono(self.name(f)),
                                    )
                                    .on_hover_text(format!(
                                        "{} · {} instructions · {} blocks",
                                        format_address(f.address),
                                        f.instruction_count,
                                        f.blocks.len()
                                    ));
                                if response.clicked() {
                                    jump = Some(f.address);
                                }
                                if response.double_clicked() {
                                    self.actions.push(Action::Show(Panel::Disassembly));
                                }
                                response.context_menu(|ui| self.address_menu(ui, f.address));
                            });
                        }
                    },
                );
            if let Some(address) = jump {
                self.navigate_address(address);
            }
            return;
        }
        egui::ScrollArea::horizontal()
            .id_salt("functions-horizontal")
            .show(ui, |ui| {
                TableBuilder::new(ui)
                    .id_salt("functions-table")
                    .striped(true)
                    .resizable(true)
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .column(Column::initial(140.0))
                    .column(Column::initial(200.0))
                    .column(Column::initial(90.0))
                    .column(Column::initial(80.0))
                    .column(Column::initial(70.0))
                    .column(Column::remainder().at_least(75.0))
                    .header(23.0, |mut header| {
                        for title in [
                            "Address",
                            "Function",
                            "Origin",
                            "Instructions",
                            "Blocks",
                            "Xrefs",
                        ] {
                            header.col(|ui| {
                                ui.strong(title);
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(
                            self.settings.row_height,
                            self.function_filter.indices.len(),
                            |mut row| {
                                let f =
                                    &analysis.functions[self.function_filter.indices[row.index()]];
                                row.set_selected(selected == Some(f.address));
                                let mut clicked = false;
                                row.col(|ui| {
                                    let r = ui.selectable_label(
                                        selected == Some(f.address),
                                        mono(format_address(f.address)),
                                    );
                                    clicked |= r.clicked();
                                    r.context_menu(|ui| self.address_menu(ui, f.address));
                                });
                                row.col(|ui| {
                                    let r = ui.selectable_label(
                                        selected == Some(f.address),
                                        self.name(f),
                                    );
                                    clicked |= r.clicked();
                                    if r.double_clicked() {
                                        self.actions.push(Action::Show(Panel::Disassembly));
                                    }
                                    r.context_menu(|ui| self.address_menu(ui, f.address));
                                });
                                row.col(|ui| {
                                    ui.label(f.origin.name());
                                });
                                row.col(|ui| {
                                    ui.label(f.instruction_count.to_string());
                                });
                                row.col(|ui| {
                                    ui.label(f.blocks.len().to_string());
                                });
                                row.col(|ui| {
                                    ui.label(f.reference_count.to_string());
                                });
                                if clicked {
                                    self.navigate_address(f.address);
                                }
                            },
                        )
                    });
            });
    }

    fn disassembly(&mut self, ui: &mut egui::Ui) {
        if self.empty(ui) {
            return;
        }
        ui.horizontal_wrapped(|ui| {
            if let Some(f) = self.function() {
                ui.colored_label(self.colors().accent, self.name(f));
                ui.label(
                    RichText::new(format!(
                        "{} instructions / {} blocks",
                        f.instruction_count,
                        f.blocks.len()
                    ))
                    .small()
                    .color(self.colors().muted),
                );
            } else {
                ui.label(
                    RichText::new("LINEAR DISASSEMBLY")
                        .small()
                        .color(self.colors().muted),
                );
            }
            if ui.small_button("Graph").clicked() {
                self.actions.push(Action::Show(Panel::Graph));
            }
            if ui.small_button("Rename").clicked() {
                self.actions.push(Action::Rename);
            }
            if ui.small_button("Comment").clicked() {
                self.actions.push(Action::Show(Panel::Inspector));
            }
        });
        if self.page_loading {
            ui.label(RichText::new("Decoding page…").color(self.colors().muted));
        }
        let Some(page) = self.page.take() else {
            ui.label("Navigate to an executable address to decode instructions.");
            return;
        };
        for warning in &page.warnings {
            ui.colored_label(self.colors().gold, warning);
        }
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!(
                    "{} · {} cached instructions",
                    page.section,
                    page.instructions.len()
                ))
                .small()
                .color(self.colors().muted),
            );
            if page.has_more
                && ui
                    .add_enabled(!self.page_loading, egui::Button::new("Load more ↓").small())
                    .clicked()
                && let Ok(address) = parse_address(&page.end_address)
            {
                self.request_page(address, true);
            }
            if ui.small_button("Function start").clicked()
                && let Some(f) = self.function()
            {
                self.navigate_address(f.address);
            }
        });
        let selected_index = page
            .instructions
            .iter()
            .position(|i| parse_address(&i.address).ok() == self.location.address);
        let scroll_to = self.scroll_disassembly.then_some(selected_index).flatten();
        self.scroll_disassembly = false;
        let mut jump = None;
        let mut reached_end = false;
        egui::ScrollArea::horizontal()
            .id_salt("disassembly-horizontal")
            .show(ui, |ui| {
                let mut table = TableBuilder::new(ui)
                    .id_salt("disassembly-table")
                    .striped(false)
                    .resizable(true)
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .column(Column::initial(21.0))
                    .column(Column::initial(118.0));
                if self.settings.show_bytes {
                    table = table.column(Column::initial(137.0));
                }
                table = table
                    .column(Column::initial(78.0))
                    .column(Column::initial(235.0))
                    .column(Column::remainder().at_least(130.0));
                if let Some(row) = scroll_to {
                    table = table.scroll_to_row(row, Some(egui::Align::Center));
                }
                table
                    .header(23.0, |mut header| {
                        header.col(|_| {});
                        header.col(|ui| {
                            ui.colored_label(self.colors().muted, "ADDRESS");
                        });
                        if self.settings.show_bytes {
                            header.col(|ui| {
                                ui.colored_label(self.colors().muted, "BYTES");
                            });
                        }
                        for text in ["MNEMONIC", "OPERANDS", "SYMBOL / COMMENT"] {
                            header.col(|ui| {
                                ui.colored_label(self.colors().muted, text);
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(
                            self.settings.row_height.max(self.settings.font_size + 4.0),
                            page.instructions.len(),
                            |mut row| {
                                if row.index() + 1 == page.instructions.len() {
                                    reached_end = true;
                                }
                                let i = &page.instructions[row.index()];
                                let address = parse_address(&i.address).unwrap_or(0);
                                let selected = self.location.address == Some(address);
                                row.set_selected(selected);
                                let analysis = self.analysis.clone();
                                let boundary =
                                    analysis.as_ref().and_then(|a| a.function_by_start(address));
                                row.col(|ui| {
                                    let incoming = self
                                        .analysis
                                        .as_ref()
                                        .map(|a| a.xrefs_to(address).count())
                                        .unwrap_or(0);
                                    if boundary.is_some() {
                                        ui.colored_label(self.colors().accent, "ƒ")
                                            .on_hover_text("Function start");
                                    } else if incoming > 0 {
                                        let r = ui
                                            .colored_label(
                                                self.colors().gold,
                                                format!("{incoming}↗"),
                                            )
                                            .on_hover_text("Incoming references");
                                        if r.clicked() {
                                            self.actions.push(Action::Show(Panel::Xrefs));
                                            jump = Some(address);
                                        }
                                    } else if let Some(target) =
                                        i.target.as_deref().and_then(|t| parse_address(t).ok())
                                        && ui
                                            .small_button(if target < address {
                                                "↑"
                                            } else {
                                                "↓"
                                            })
                                            .on_hover_text(format!(
                                                "Follow {}",
                                                format_address(target)
                                            ))
                                            .clicked()
                                    {
                                        jump = Some(target);
                                    }
                                });
                                row.col(|ui| {
                                    let r = ui.selectable_label(
                                        selected,
                                        mono(&i.address).color(if boundary.is_some() {
                                            self.colors().accent
                                        } else {
                                            self.colors().muted
                                        }),
                                    );
                                    if r.clicked() {
                                        jump = Some(address);
                                    }
                                    r.context_menu(|ui| self.instruction_menu(ui, address, i));
                                });
                                if self.settings.show_bytes {
                                    row.col(|ui| {
                                        ui.add(
                                            egui::Label::new(
                                                mono(&i.bytes).color(self.colors().muted),
                                            )
                                            .truncate(),
                                        )
                                        .on_hover_text(&i.bytes);
                                    });
                                }
                                row.col(|ui| {
                                    let color =
                                        instruction_color(&i.flow, i.invalid, self.colors());
                                    let r = ui.add(
                                        egui::Label::new(mono(&i.mnemonic).color(color))
                                            .sense(Sense::click()),
                                    );
                                    if r.clicked() {
                                        jump = Some(address);
                                    }
                                    r.context_menu(|ui| self.instruction_menu(ui, address, i));
                                });
                                row.col(|ui| {
                                    let r = ui.add(
                                        egui::Label::new(assembly_job(
                                            &i.operands,
                                            self.settings.font_size,
                                            self.colors(),
                                        ))
                                        .truncate()
                                        .sense(Sense::click()),
                                    );
                                    if r.clicked() {
                                        jump = Some(address);
                                    }
                                    if r.double_clicked() {
                                        jump = i
                                            .target
                                            .as_deref()
                                            .and_then(|t| parse_address(t).ok())
                                            .or(Some(address));
                                    }
                                    r.context_menu(|ui| self.instruction_menu(ui, address, i));
                                });
                                row.col(|ui| {
                                    if let Some(f) = boundary {
                                        ui.colored_label(self.colors().accent, self.name(f));
                                    }
                                    if let Some(target) =
                                        i.target.as_deref().and_then(|t| parse_address(t).ok())
                                        && let Some(f) = self
                                            .analysis
                                            .as_ref()
                                            .and_then(|a| a.function_by_start(target))
                                        && ui.link(self.name(f)).clicked()
                                    {
                                        jump = Some(target);
                                    }
                                    if let Some((_, p)) = &self.project
                                        && let Some(a) = self
                                            .annotation_indices
                                            .get(&address)
                                            .and_then(|i| p.annotations.get(*i))
                                    {
                                        ui.add(
                                            egui::Label::new(
                                                mono(format!(
                                                    "; {} {}",
                                                    a.label.as_deref().unwrap_or(""),
                                                    a.note
                                                ))
                                                .color(self.colors().gold),
                                            )
                                            .truncate(),
                                        )
                                        .on_hover_text(&a.note);
                                    }
                                });
                            },
                        )
                    });
            });
        let load_more = page.has_more
            && !self.page_loading
            && reached_end
            && ui.input(|i| i.smooth_scroll_delta.y < 0.0);
        let next = parse_address(&page.end_address).ok();
        self.page = Some(page);
        if load_more && let Some(address) = next {
            self.request_page(address, true);
        }
        if let Some(address) = jump {
            self.navigate_address(address);
        }
    }

    fn instruction_menu(
        &mut self,
        ui: &mut egui::Ui,
        address: u64,
        instruction: &ura_core::InstructionView,
    ) {
        if ui.button("Copy instruction").clicked() {
            ui.ctx()
                .copy_text(format!("{}  {}", instruction.address, instruction.text));
            ui.close();
        }
        if ui.button("Copy bytes").clicked() {
            ui.ctx().copy_text(instruction.bytes.clone());
            ui.close();
        }
        ui.separator();
        self.address_menu(ui, address);
    }
    pub fn address_menu(&mut self, ui: &mut egui::Ui, address: u64) {
        for (title, panel) in [
            ("Open disassembly", Panel::Disassembly),
            ("Open graph", Panel::Graph),
            ("Open hex", Panel::Hex),
            ("Show references", Panel::Xrefs),
            ("Edit annotation", Panel::Inspector),
        ] {
            if ui.button(title).clicked() {
                self.navigate_address(address);
                self.actions.push(Action::Show(panel));
                ui.close();
            }
        }
        if ui.button("Rename function…").clicked() {
            self.navigate_address(address);
            self.actions.push(Action::Rename);
            ui.close();
        }
        if ui.button("Define function").clicked() {
            self.navigate_address(address);
            self.actions.push(Action::Manual(true));
            ui.close();
        }
        if ui.button("Copy address").clicked() {
            ui.ctx().copy_text(format_address(address));
            ui.close();
        }
    }

    fn hex(&mut self, ui: &mut egui::Ui) {
        if self.empty(ui) {
            return;
        }
        let binary = self.binary.clone().unwrap();
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new("BYTES PER ROW")
                    .small()
                    .color(self.colors().muted),
            );
            for n in [8, 16, 32] {
                if ui
                    .selectable_value(&mut self.settings.hex_columns, n, n.to_string())
                    .changed()
                {
                    self.scroll_hex = true;
                }
            }
            if ui.small_button("Go to offset…").clicked() {
                self.actions.push(Action::Palette);
            }
            ui.label(
                RichText::new(format!("{} bytes", binary.bytes().len()))
                    .small()
                    .color(self.colors().muted),
            );
        });
        let columns = self.settings.hex_columns;
        let count = binary.bytes().len().div_ceil(columns);
        let selected = self.location.file_offset.map(|o| o as usize);
        let font = FontId::monospace(self.settings.font_size);
        let cell = self.settings.font_size * 1.85;
        let ascii_cell = self.settings.font_size * 0.66;
        let address_width = 112.0;
        let ascii_start = address_width + cell * columns as f32 + 20.0;
        let width = ascii_start + ascii_cell * columns as f32 + 12.0;
        ui.label(
            RichText::new("FILE OFFSET        HEXADECIMAL                                  ASCII")
                .monospace()
                .color(self.colors().muted),
        );
        let mut jump = None;
        egui::ScrollArea::horizontal()
            .id_salt("hex-horizontal")
            .show(ui, |ui| {
                let mut scroll = egui::ScrollArea::vertical().id_salt("hex-vertical");
                if self.scroll_hex {
                    if let Some(offset) = selected {
                        scroll = scroll.vertical_scroll_offset(
                            (offset / columns) as f32
                                * (self.settings.row_height + ui.spacing().item_spacing.y),
                        );
                    }
                    self.scroll_hex = false;
                }
                scroll.show_rows(ui, self.settings.row_height, count, |ui, rows| {
                    for row in rows {
                        let (rect, response) = ui.allocate_exact_size(
                            egui::vec2(width, self.settings.row_height),
                            Sense::click(),
                        );
                        let offset = row * columns;
                        let painter = ui.painter();
                        if row % 2 != 0 {
                            painter.rect_filled(rect, 0.0, self.colors().panel);
                        }
                        painter.text(
                            rect.left_center(),
                            Align2::LEFT_CENTER,
                            format!("{offset:08X}"),
                            font.clone(),
                            self.colors().muted,
                        );
                        for (j, byte) in binary.bytes()
                            [offset..binary.bytes().len().min(offset + columns)]
                            .iter()
                            .enumerate()
                        {
                            let x = rect.left() + address_width + cell * j as f32;
                            let ax = rect.left() + ascii_start + ascii_cell * j as f32;
                            if selected == Some(offset + j) {
                                painter.rect_filled(
                                    egui::Rect::from_min_size(
                                        egui::pos2(x - 2.0, rect.top()),
                                        egui::vec2(cell, rect.height()),
                                    ),
                                    1.0,
                                    self.colors().selected,
                                );
                                painter.rect_filled(
                                    egui::Rect::from_min_size(
                                        egui::pos2(ax - 1.0, rect.top()),
                                        egui::vec2(ascii_cell, rect.height()),
                                    ),
                                    1.0,
                                    self.colors().selected,
                                );
                            }
                            painter.text(
                                egui::pos2(x, rect.center().y),
                                Align2::LEFT_CENTER,
                                format!("{byte:02X}"),
                                font.clone(),
                                if *byte == 0 {
                                    self.colors().muted
                                } else {
                                    self.colors().text
                                },
                            );
                            painter.text(
                                egui::pos2(ax, rect.center().y),
                                Align2::LEFT_CENTER,
                                if (0x20..=0x7e).contains(byte) {
                                    char::from(*byte)
                                } else {
                                    '·'
                                },
                                font.clone(),
                                if (0x20..=0x7e).contains(byte) {
                                    self.colors().accent
                                } else {
                                    self.colors().muted
                                },
                            );
                        }
                        if response.clicked()
                            && let Some(pos) = response.interact_pointer_pos()
                        {
                            let x = pos.x - rect.left();
                            let col = if x >= ascii_start {
                                ((x - ascii_start) / ascii_cell).floor() as usize
                            } else {
                                ((x - address_width) / cell).max(0.0).floor() as usize
                            }
                            .min(columns - 1);
                            if offset + col < binary.bytes().len() {
                                jump = Some(offset + col);
                            }
                        }
                        response.context_menu(|ui| {
                            if ui.button("Copy row bytes").clicked() {
                                ui.ctx().copy_text(
                                    binary.bytes()
                                        [offset..binary.bytes().len().min(offset + columns)]
                                        .iter()
                                        .map(|b| format!("{b:02X}"))
                                        .collect::<Vec<_>>()
                                        .join(" "),
                                );
                                ui.close();
                            }
                        });
                    }
                });
            });
        if let Some(offset) = jump {
            self.actions.push(Action::Navigate(
                Location::offset(binary.analysis(), offset as u64),
                true,
            ));
        }
    }

    fn strings_view(&mut self, ui: &mut egui::Ui) {
        if self.empty(ui) {
            return;
        }
        ui.horizontal_wrapped(|ui| {
            ui.label("Minimum");
            ui.add(egui::DragValue::new(&mut self.settings.min_string).range(2..=512));
            ui.checkbox(&mut self.settings.ascii, "ASCII");
            ui.checkbox(&mut self.settings.utf16, "UTF-16LE");
            if ui
                .add_enabled(!self.scanning, egui::Button::new("Rescan"))
                .clicked()
            {
                self.actions.push(Action::Scan);
            }
            if self.scanning {
                ui.spinner();
            }
        });
        if ui
            .add(
                egui::TextEdit::singleline(&mut self.string_filter.query)
                    .hint_text("Search strings…")
                    .desired_width(f32::INFINITY),
            )
            .changed()
        {
            self.string_filter.dirty = true;
        }
        ui.horizontal(|ui| {
            for (i, label) in ["All", "ASCII", "UTF-16LE"].iter().enumerate() {
                if ui
                    .selectable_value(&mut self.string_encoding, i, *label)
                    .changed()
                {
                    self.string_filter.dirty = true;
                }
            }
            if ui
                .checkbox(&mut self.string_filter.descending, "Descending offset")
                .changed()
            {
                self.string_filter.dirty = true;
            }
        });
        let Some(strings) = self.strings.take() else {
            ui.label("Scanning strings…");
            return;
        };
        if self.string_filter.dirty {
            let q = self.string_filter.query.to_lowercase();
            self.string_filter.indices = strings
                .strings
                .iter()
                .enumerate()
                .filter(|(_, s)| {
                    (self.string_encoding == 0
                        || s.encoding
                            == if self.string_encoding == 1 {
                                "ASCII"
                            } else {
                                "UTF-16LE"
                            })
                        && s.value.to_lowercase().contains(&q)
                })
                .map(|(i, _)| i)
                .collect();
            if self.string_filter.descending {
                self.string_filter.indices.reverse();
            }
            self.string_filter.dirty = false;
        }
        ui.label(
            RichText::new(format!(
                "{} / {} strings{}",
                self.string_filter.indices.len(),
                strings.strings.len(),
                if strings.truncated {
                    " · partial result"
                } else {
                    ""
                }
            ))
            .color(self.colors().muted),
        );
        let binary = self.binary.clone().unwrap();
        egui::ScrollArea::horizontal()
            .id_salt("strings-horizontal")
            .show(ui, |ui| {
                TableBuilder::new(ui)
                    .id_salt("strings-table")
                    .striped(true)
                    .resizable(true)
                    .column(Column::initial(115.0))
                    .column(Column::initial(145.0))
                    .column(Column::initial(80.0))
                    .column(Column::initial(60.0))
                    .column(Column::remainder().at_least(250.0))
                    .header(24.0, |mut header| {
                        for title in ["File offset", "Address", "Encoding", "Length", "Value"] {
                            header.col(|ui| {
                                ui.strong(title);
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(
                            self.settings.row_height,
                            self.string_filter.indices.len(),
                            |mut row| {
                                let s = &strings.strings[self.string_filter.indices[row.index()]];
                                row.col(|ui| {
                                    if ui.link(mono(&s.offset)).clicked()
                                        && let Ok(offset) = parse_address(&s.offset)
                                    {
                                        self.actions.push(Action::Navigate(
                                            Location::offset(binary.analysis(), offset),
                                            true,
                                        ));
                                        self.actions.push(Action::Show(Panel::Hex));
                                    }
                                });
                                row.col(|ui| {
                                    if let Some(address) = &s.address {
                                        if ui.link(mono(address)).clicked()
                                            && let Ok(address) = parse_address(address)
                                        {
                                            self.navigate_address(address);
                                            self.actions.push(Action::Show(Panel::Disassembly));
                                        }
                                    } else {
                                        ui.colored_label(self.colors().muted, "unmapped");
                                    }
                                });
                                row.col(|ui| {
                                    ui.label(&s.encoding);
                                });
                                row.col(|ui| {
                                    ui.label(s.length.to_string());
                                });
                                row.col(|ui| {
                                    let r = ui
                                        .add(
                                            egui::Label::new(mono(&s.value))
                                                .truncate()
                                                .sense(Sense::click()),
                                        )
                                        .on_hover_text(&s.value);
                                    if r.clicked()
                                        && let Ok(offset) = parse_address(&s.offset)
                                    {
                                        self.actions.push(Action::Navigate(
                                            Location::offset(binary.analysis(), offset),
                                            true,
                                        ));
                                    }
                                    r.context_menu(|ui| {
                                        if ui.button("Copy string").clicked() {
                                            ui.ctx().copy_text(s.value.clone());
                                            ui.close();
                                        }
                                    });
                                });
                            },
                        )
                    });
            });
        self.strings = Some(strings);
    }

    fn xrefs(&mut self, ui: &mut egui::Ui) {
        if self.empty(ui) {
            return;
        }
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(&mut self.xref_function, false, "Exact address");
            ui.selectable_value(&mut self.xref_function, true, "Function");
            ui.selectable_value(&mut self.xref_outgoing, false, "Incoming");
            ui.selectable_value(&mut self.xref_outgoing, true, "Outgoing");
        });
        if ui
            .add(
                egui::TextEdit::singleline(&mut self.xref_filter.query)
                    .hint_text("Filter type, source or target…")
                    .desired_width(f32::INFINITY),
            )
            .changed()
        {
            self.xref_filter.dirty = true;
        }
        if ui
            .checkbox(&mut self.xref_filter.descending, "Descending source")
            .changed()
        {
            self.xref_filter.dirty = true;
        }
        let Some(analysis) = self.analysis.clone() else {
            ui.label("Run analysis to index references.");
            return;
        };
        let Some(address) = self.location.address else {
            ui.label("Select a mapped address.");
            return;
        };
        let function = self.function();
        let (start, end) = if self.xref_function {
            function
                .map(|f| (f.address, f.end))
                .unwrap_or((address, address.saturating_add(1)))
        } else {
            (address, address.saturating_add(1))
        };
        let key = Some((start, self.xref_function, self.xref_outgoing));
        if self.xref_filter.dirty || self.xref_key != key {
            let q = self.xref_filter.query.to_lowercase();
            self.xref_filter.indices = analysis
                .xrefs
                .iter()
                .enumerate()
                .filter(|(_, x)| {
                    let scope = if self.xref_outgoing { x.from } else { x.to };
                    scope >= start
                        && scope < end
                        && (q.is_empty()
                            || x.kind.name().to_lowercase().contains(&q)
                            || format!("{:x} {:x}", x.from, x.to).contains(&q))
                })
                .map(|(i, _)| i)
                .collect();
            self.xref_filter
                .indices
                .sort_by_key(|&i| (analysis.xrefs[i].from, analysis.xrefs[i].to));
            if self.xref_filter.descending {
                self.xref_filter.indices.reverse();
            }
            self.xref_filter.dirty = false;
            self.xref_key = key;
        }
        ui.label(
            RichText::new(format!(
                "{} references · {}",
                self.xref_filter.indices.len(),
                format_address(start)
            ))
            .small()
            .color(self.colors().muted),
        );
        let binary = self.binary.clone().unwrap();
        egui::ScrollArea::both().id_salt("xref-scroll").show_rows(
            ui,
            self.settings.row_height * 2.0,
            self.xref_filter.indices.len(),
            |ui, range| {
                for row in range {
                    let x = &analysis.xrefs[self.xref_filter.indices[row]];
                    ui.horizontal(|ui| {
                        if ui.link(mono(format_address(x.from))).clicked() {
                            self.navigate_address(x.from);
                            self.actions.push(Action::Show(Panel::Disassembly));
                        }
                        ui.label("→");
                        if ui.link(mono(format_address(x.to))).clicked() {
                            self.navigate_address(x.to);
                        }
                    });
                    let source = analysis
                        .function_containing(x.from)
                        .map(|f| self.name(f))
                        .unwrap_or_default();
                    let section = binary
                        .analysis()
                        .section_containing_address(x.to)
                        .map(|s| s.name.as_str())
                        .unwrap_or("unmapped");
                    ui.colored_label(
                        self.colors().muted,
                        format!(
                            "{} {} · {} · {}",
                            x.kind.name(),
                            x.data_kind.map(|k| k.name()).unwrap_or(""),
                            source,
                            section
                        ),
                    );
                }
            },
        );
    }

    fn overview(&mut self, ui: &mut egui::Ui) {
        if self.empty(ui) {
            return;
        }
        let binary = self.binary.clone().unwrap();
        let a = binary.analysis();
        egui::ScrollArea::both().show(ui, |ui| {
            if let Some(info) = &self.info {
                ui.label(RichText::new(&info.file_name).size(18.0).strong());
                ui.label(RichText::new(&info.path).color(self.colors().muted));
                ui.separator();
                egui::Grid::new("binary-facts")
                    .num_columns(2)
                    .spacing([20.0, 7.0])
                    .show(ui, |ui| {
                        for (label, value) in [
                            ("Format", info.format.clone()),
                            (
                                "Architecture",
                                format!(
                                    "{} · {} bit · {} endian",
                                    info.architecture, info.bitness, info.endianness
                                ),
                            ),
                            ("Image base", info.image_base.clone()),
                            (
                                "Entry point",
                                info.entry_point.clone().unwrap_or_else(|| "None".into()),
                            ),
                            ("File size", format!("{} bytes", info.file_size)),
                            ("Object kind", info.object_kind.clone()),
                            ("Debug symbols", info.has_debug_symbols.to_string()),
                        ] {
                            ui.colored_label(self.colors().muted, label);
                            ui.label(mono(value));
                            ui.end_row();
                        }
                    });
                ui.add_space(8.0);
                ui.colored_label(self.colors().muted, "SHA-256");
                ui.add(egui::Label::new(mono(&info.sha256)).wrap());
            }
            ui.add_space(12.0);
            ui.strong("Sections");
            ui.separator();
            egui::Grid::new("sections")
                .striped(true)
                .spacing([20.0, 6.0])
                .show(ui, |ui| {
                    for title in [
                        "Name",
                        "Address",
                        "File offset",
                        "Mapped size",
                        "File size",
                        "Permissions",
                    ] {
                        ui.colored_label(self.colors().muted, title);
                    }
                    ui.end_row();
                    for s in &a.sections {
                        if ui.link(&s.name).clicked() {
                            self.navigate_address(s.address);
                        }
                        ui.label(mono(format_address(s.address)));
                        ui.label(mono(
                            s.file_offset
                                .map(format_address)
                                .unwrap_or_else(|| "—".into()),
                        ));
                        ui.label(s.size.to_string());
                        ui.label(s.file_size.to_string());
                        ui.label(mono(s.permissions()));
                        ui.end_row();
                    }
                });
            if let Some(analysis) = &self.analysis {
                ui.add_space(12.0);
                ui.strong("Analysis");
                ui.label(format!(
                    "{} functions · {} blocks · {} instructions · {} references · {} ms",
                    analysis.report.function_count,
                    analysis.report.block_count,
                    analysis.report.instruction_count,
                    analysis.report.xref_count,
                    analysis.report.elapsed_ms
                ));
                if analysis.report.cancelled || analysis.report.truncated {
                    ui.colored_label(
                        self.colors().gold,
                        "Analysis is partial; inspect Messages for diagnostics.",
                    );
                }
            }
        });
    }

    fn inspector(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.label(
                RichText::new("SELECTION")
                    .small()
                    .color(self.colors().muted),
            );
            if let Some(address) = self.location.address {
                ui.label(mono(format_address(address)).color(self.colors().accent));
            }
            if let Some(offset) = self.location.file_offset {
                ui.label(mono(format!("File {offset:#x}")));
            }
            if let Some(binary) = &self.binary
                && let Some(section) = self
                    .location
                    .address
                    .and_then(|v| binary.analysis().section_containing_address(v))
            {
                ui.label(format!("{} · {}", section.name, section.permissions()));
            }
            if let Some(f) = self.function() {
                ui.separator();
                ui.label(RichText::new("FUNCTION").small().color(self.colors().muted));
                ui.label(self.name(f));
                ui.label(mono(format!(
                    "{} — {}",
                    format_address(f.address),
                    format_address(f.end)
                )));
                ui.label(format!("{} · {} bytes", f.origin.name(), f.size()));
                ui.label(format!(
                    "{} instructions · {} blocks",
                    f.instruction_count,
                    f.blocks.len()
                ));
                let callers = f.callers.clone();
                let callees = f.callees.clone();
                ui.collapsing(format!("Callers ({})", callers.len()), |ui| {
                    for address in callers {
                        if ui.link(mono(format_address(address))).clicked() {
                            self.navigate_address(address);
                        }
                    }
                });
                ui.collapsing(format!("Callees ({})", callees.len()), |ui| {
                    for address in callees {
                        if ui.link(mono(format_address(address))).clicked() {
                            self.navigate_address(address);
                        }
                    }
                });
                if ui.button("Rename function…").clicked() {
                    self.actions.push(Action::Rename);
                }
            }
            ui.separator();
            if ui.button("Show references").clicked() {
                self.actions.push(Action::Show(Panel::Xrefs));
            }
            ui.add_space(8.0);
            ui.label(
                RichText::new("ANNOTATION")
                    .small()
                    .color(self.colors().muted),
            );
            if self.project.is_none() {
                ui.label("Create a project to persist names and notes.");
                if ui.button("Create project…").clicked() {
                    self.actions.push(Action::NewProject);
                }
            }
            ui.add_enabled_ui(
                self.project.is_some() && self.location.address.is_some(),
                |ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.annotation_label)
                            .hint_text("Label")
                            .desired_width(f32::INFINITY),
                    );
                    ui.add(
                        egui::TextEdit::multiline(&mut self.annotation_note)
                            .hint_text("Analysis notes…")
                            .desired_rows(5)
                            .desired_width(f32::INFINITY),
                    );
                    if ui.button("Save annotation    Ctrl+Enter").clicked() {
                        self.actions.push(Action::SaveAnnotation);
                    }
                    let id = self
                        .project
                        .as_ref()
                        .and_then(|(_, p)| {
                            p.annotations
                                .iter()
                                .find(|a| parse_address(&a.address).ok() == self.location.address)
                        })
                        .map(|a| a.id);
                    if let Some(id) = id
                        && ui.button("Delete annotation").clicked()
                    {
                        self.actions.push(Action::DeleteAnnotation(id));
                    }
                },
            );
            if let Some((path, p)) = self.project.take() {
                let annotations = &p.annotations;
                ui.separator();
                ui.collapsing(
                    format!("Project annotations ({})", annotations.len()),
                    |ui| {
                        for a in annotations.iter().take(1000) {
                            if ui
                                .link(format!(
                                    "{} {}",
                                    a.address,
                                    a.label.as_deref().unwrap_or("")
                                ))
                                .on_hover_text(&a.note)
                                .clicked()
                                && let Ok(address) = parse_address(&a.address)
                            {
                                self.navigate_address(address);
                            }
                        }
                        if annotations.len() > 1000 {
                            ui.colored_label(
                                self.colors().gold,
                                "Showing first 1000 annotations; use the palette to search all.",
                            );
                        }
                    },
                );
                self.project = Some((path, p));
            }
        });
    }
    fn messages_view(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!("{} messages", self.messages.len()))
                    .small()
                    .color(self.colors().muted),
            );
            if ui.small_button("Clear").clicked() {
                self.messages.clear();
            }
            if ui.small_button("Copy").clicked() {
                ui.ctx().copy_text(
                    self.messages
                        .iter()
                        .map(|(error, text)| {
                            format!("{} {text}", if *error { "[warning]" } else { "[info]" })
                        })
                        .collect::<Vec<_>>()
                        .join("\n"),
                );
            }
        });
        egui::ScrollArea::both()
            .id_salt("messages-scroll")
            .stick_to_bottom(true)
            .show_rows(ui, 20.0, self.messages.len(), |ui, range| {
                for row in range {
                    let (error, text) = &self.messages[row];
                    ui.horizontal(|ui| {
                        ui.colored_label(
                            if *error {
                                self.colors().gold
                            } else {
                                self.colors().accent
                            },
                            if *error { "!" } else { "·" },
                        );
                        ui.label(mono(text).size(11.0));
                    });
                }
            });
    }

    pub fn dialogs(&mut self, ctx: &egui::Context) {
        self.decompiler_editor(ctx);
        if self.about_open {
            let mut open = true;
            egui::Window::new("About URA")
                .open(&mut open)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.image((self.icon.id(), egui::vec2(96.0, 96.0)));
                        ui.vertical(|ui| {
                            ui.heading("URA");
                            ui.label(format!(
                                "Ultimate Reverse Engineer · {}",
                                env!("CARGO_PKG_VERSION")
                            ));
                            ui.label("Native Rust static analysis · MIT license");
                            ui.hyperlink_to(
                                "Source and documentation",
                                "https://github.com/entrenchedosx/URA",
                            );
                        });
                    });
                    ui.separator();
                    ui.label("Ctrl+O Open · Ctrl+G Go to · Ctrl+K Commands · F2 Rename");
                    ui.label("Space Linear/Graph · Alt+Left/Right History · Ctrl+, Preferences");
                    ui.label("Arrows/PageUp/PageDown Select instruction · Enter Follow branch");
                    ui.label("Graph: drag to pan · wheel to zoom · double-click to open");
                });
            self.about_open = open;
        }
        if self.palette_open {
            self.palette(ctx);
        }
        if self.settings_open {
            let mut open = true;
            egui::Window::new("Preferences").open(&mut open).resizable(false).collapsible(false).show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.settings.theme, crate::design::Theme::Classic, "Classic light");
                    ui.selectable_value(&mut self.settings.theme, crate::design::Theme::Dark, "Professional dark");
                });
                ui.add(egui::Slider::new(&mut self.settings.ui_font_size, 10.0..=18.0).text("Interface font size"));
                ui.add(egui::Slider::new(&mut self.settings.graph_font_size, 10.0..=18.0).text("Graph font size"));
                ui.add(egui::Slider::new(&mut self.settings.font_size, 10.0..=18.0).text("Code font size"));
                ui.add(egui::Slider::new(&mut self.settings.row_height, 16.0..=30.0).text("Row height"));
                ui.checkbox(&mut self.settings.show_bytes, "Show instruction bytes");
                ui.label(RichText::new("Columns resize by dragging table dividers. Settings save automatically.").color(self.colors().muted));
                ui.separator();
                ui.collapsing("Visible panels", |ui| {
                    for panel in Panel::ALL {
                        let mut visible = self.visible_panels.contains(&panel);
                        if ui.checkbox(&mut visible, panel.title()).changed() { self.actions.push(Action::TogglePanel(panel)); }
                    }
                });
                if ui.button("Reset panel layout").clicked() { self.actions.push(Action::ResetLayout); }
                if ui.button("Reset preferences").clicked() { self.settings = Settings::default(); }
                if ui.button("Close").clicked() { self.settings_open = false; }
            });
            self.settings_open &= open;
        }
        if self.rename_open {
            let mut open = true;
            egui::Window::new("Rename function")
                .open(&mut open)
                .resizable(false)
                .collapsible(false)
                .show(ctx, |ui| {
                    ui.label(mono(
                        self.rename_address.map(format_address).unwrap_or_default(),
                    ));
                    let response = ui.add(
                        egui::TextEdit::singleline(&mut self.rename_value).desired_width(300.0),
                    );
                    if !response.has_focus() && !ctx.egui_wants_keyboard_input() {
                        response.request_focus();
                    }
                    ui.label(
                        RichText::new("An empty name restores the imported or generated name.")
                            .small()
                            .color(self.colors().muted),
                    );
                    if ui.button("Save name").clicked()
                        || response.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter))
                    {
                        self.actions.push(Action::SaveRename);
                    }
                });
            self.rename_open &= open;
        }
    }
    fn palette(&mut self, ctx: &egui::Context) {
        let mut open = true;
        egui::Window::new("Go to / Commands")
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .default_width(640.0)
            .anchor(Align2::CENTER_TOP, [0.0, 95.0])
            .show(ctx, |ui| {
                let response = ui.add(
                    egui::TextEdit::singleline(&mut self.palette_query)
                        .hint_text(
                            "Address, @file offset, +delta, .text+offset, symbol or command…",
                        )
                        .desired_width(f32::INFINITY),
                );
                if response.changed() || self.palette_focus {
                    self.rebuild_palette();
                    self.palette_index = 0;
                    if self.palette_focus {
                        response.request_focus();
                        self.palette_focus = false;
                    }
                }
                if ui.input(|i| i.key_pressed(Key::ArrowDown)) {
                    self.palette_index =
                        (self.palette_index + 1).min(self.palette_items.len().saturating_sub(1));
                }
                if ui.input(|i| i.key_pressed(Key::ArrowUp)) {
                    self.palette_index = self.palette_index.saturating_sub(1);
                }
                ui.label(
                    RichText::new("Enter to open · ↑ / ↓ to select · Escape to close")
                        .small()
                        .color(self.colors().muted),
                );
                let mut chosen = None;
                egui::ScrollArea::vertical()
                    .max_height(380.0)
                    .show(ui, |ui| {
                        for (i, (label, detail, _)) in self.palette_items.iter().enumerate() {
                            let response = ui.selectable_label(
                                i == self.palette_index,
                                format!("{label}    {detail}"),
                            );
                            if response.clicked() {
                                chosen = Some(i);
                            }
                            if i == self.palette_index
                                && ui.input(|i| {
                                    i.key_pressed(Key::ArrowDown) || i.key_pressed(Key::ArrowUp)
                                })
                            {
                                response.scroll_to_me(Some(egui::Align::Center));
                            }
                        }
                        if self.palette_items.is_empty() {
                            ui.colored_label(
                                self.colors().muted,
                                "No matching address, symbol or command.",
                            );
                        }
                    });
                if ui.input(|i| i.key_pressed(Key::Enter)) && !self.palette_items.is_empty() {
                    chosen = Some(self.palette_index);
                }
                if let Some(index) = chosen
                    && let Some((_, _, action)) = self.palette_items.get(index)
                {
                    self.actions.push(action.clone());
                    self.palette_open = false;
                }
            });
        self.palette_open &= open;
    }
    fn rebuild_palette(&mut self) {
        self.palette_items.clear();
        let query = self.palette_query.trim();
        let q = query.to_lowercase();
        let commands = [
            ("Open binary…", Action::OpenDialog(false)),
            ("Open project…", Action::OpenDialog(true)),
            ("Create project…", Action::NewProject),
            ("Analyze functions", Action::Analyze),
            ("Cancel analysis", Action::Cancel),
            ("Rescan strings", Action::Scan),
            ("Rename function…", Action::Rename),
            ("Define function here", Action::Manual(true)),
            ("Remove manual function", Action::Manual(false)),
            ("Export annotations…", Action::Export),
            ("Reset layout", Action::ResetLayout),
            ("Preferences", Action::Settings),
        ];
        if let Some(binary) = &self.binary
            && !query.is_empty()
            && let Ok(location) = crate::navigation::resolve(
                query,
                binary.analysis(),
                self.location,
                binary.bytes().len() as u64,
            )
        {
            self.palette_items.push((
                format!("Go to {query}"),
                location
                    .address
                    .map(format_address)
                    .unwrap_or_else(|| "file offset".into()),
                Action::Navigate(location, true),
            ));
        }
        for (name, action) in commands {
            if name.to_lowercase().contains(&q) {
                self.palette_items
                    .push((name.into(), "command".into(), action));
            }
        }
        for p in Panel::ALL {
            if p.title().to_lowercase().contains(&q) {
                self.palette_items.push((
                    format!("Show {}", p.title()),
                    "panel".into(),
                    Action::Show(p),
                ));
            }
        }
        if query.is_empty() {
            return;
        }
        if let Some(analysis) = &self.analysis {
            for f in &analysis.functions {
                let name = self.name(f);
                if name.to_lowercase().contains(&q) || format!("{:x}", f.address).contains(&q) {
                    self.palette_items.push((
                        name,
                        format_address(f.address),
                        Action::Navigate(self.address_location(f.address), true),
                    ));
                    if self.palette_items.len() >= 80 {
                        return;
                    }
                }
            }
        }
        if let Some(binary) = &self.binary {
            for section in &binary.analysis().sections {
                if section.name.to_lowercase().contains(&q) {
                    self.palette_items.push((
                        section.name.clone(),
                        format_address(section.address),
                        Action::Navigate(self.address_location(section.address), true),
                    ));
                }
            }
            for s in &binary.analysis().symbols {
                if let Some(address) = s.address
                    && s.name.to_lowercase().contains(&q)
                {
                    self.palette_items.push((
                        s.name.clone(),
                        format_address(address),
                        Action::Navigate(self.address_location(address), true),
                    ));
                    if self.palette_items.len() >= 80 {
                        return;
                    }
                }
            }
            for s in &binary.analysis().exports {
                if s.name.to_lowercase().contains(&q) {
                    self.palette_items.push((
                        s.name.clone(),
                        format_address(s.address),
                        Action::Navigate(self.address_location(s.address), true),
                    ));
                    if self.palette_items.len() >= 80 {
                        return;
                    }
                }
            }
        }
        if let Some((_, p)) = &self.project {
            for a in &p.annotations {
                if (a.label.as_deref().unwrap_or("").to_lowercase().contains(&q)
                    || a.note.to_lowercase().contains(&q))
                    && let Ok(address) = parse_address(&a.address)
                {
                    self.palette_items.push((
                        a.label
                            .clone()
                            .unwrap_or_else(|| a.note.chars().take(50).collect()),
                        a.address.clone(),
                        Action::Navigate(self.address_location(address), true),
                    ));
                    if self.palette_items.len() >= 80 {
                        return;
                    }
                }
            }
        }
    }
}

pub(crate) fn instruction_color(
    flow: &str,
    invalid: bool,
    colors: crate::design::Palette,
) -> Color32 {
    if invalid {
        colors.error
    } else if flow.contains("call") {
        colors.gold
    } else if flow.contains("jump") || flow == "return" {
        colors.branch
    } else {
        colors.accent
    }
}

pub(crate) fn assembly_job(
    text: &str,
    size: f32,
    colors: crate::design::Palette,
) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    for token in text.split_inclusive(|c: char| !c.is_alphanumeric() && c != '_') {
        let word = token
            .trim_matches(|c: char| !c.is_alphanumeric())
            .to_ascii_lowercase();
        let color = if word.starts_with("0x")
            || word.chars().next().is_some_and(|c| c.is_ascii_digit())
            || word.ends_with('h')
                && word.len() > 1
                && word[..word.len() - 1]
                    .chars()
                    .all(|c| c.is_ascii_hexdigit())
        {
            colors.gold
        } else if matches!(
            word.as_str(),
            "rax"
                | "rbx"
                | "rcx"
                | "rdx"
                | "rsp"
                | "rbp"
                | "rsi"
                | "rdi"
                | "rip"
                | "eax"
                | "ebx"
                | "ecx"
                | "edx"
                | "esp"
                | "ebp"
                | "esi"
                | "edi"
                | "ax"
                | "al"
                | "cl"
                | "dl"
                | "r8"
                | "r9"
                | "r10"
                | "r11"
                | "r12"
                | "r13"
                | "r14"
                | "r15"
        ) || word.starts_with("xmm")
        {
            colors.register
        } else {
            colors.text
        };
        job.append(
            token,
            0.0,
            egui::TextFormat {
                font_id: FontId::monospace(size),
                color,
                ..Default::default()
            },
        );
    }
    job
}
