use crate::app::{Action, Panel, Workspace};
use eframe::egui::{self, RichText};

fn root_menu(ui: &mut egui::Ui, title: &str, key: egui::Key, body: impl FnOnce(&mut egui::Ui)) {
    let response = ui.menu_button(title, body);
    if ui.input_mut(|i| i.consume_key(egui::Modifiers::ALT, key)) {
        egui::Popup::open_id(
            ui.ctx(),
            egui::Popup::default_response_id(&response.response),
        );
        response.response.request_focus();
        ui.ctx().request_repaint();
    }
}

fn command(
    ui: &mut egui::Ui,
    enabled: bool,
    text: &str,
    action: Action,
    actions: &mut Vec<Action>,
) {
    if ui.add_enabled(enabled, egui::Button::new(text)).clicked() {
        actions.push(action);
        ui.close();
    }
}

impl Workspace {
    pub fn toolbar(&mut self, ui: &mut egui::Ui) {
        let loaded = self.binary.is_some();
        let project = self.project.is_some();
        let function = self.function().is_some();
        let manual = self.function().is_some_and(|f| {
            self.project.as_ref().is_some_and(|(_, p)| {
                p.manual_functions
                    .iter()
                    .any(|m| ura_core::parse_address(&m.address).ok() == Some(f.address))
            })
        });
        let back = self.history.index > 0;
        let forward = self.history.index + 1 < self.history.entries.len();
        egui::MenuBar::new().ui(ui, |ui| {
            ui.set_min_height(21.0);
            root_menu(ui, "File", egui::Key::F, |ui| {
                for (enabled, label, action) in [
                    (
                        !self.opening,
                        "Open binary…     Ctrl+O",
                        Action::OpenDialog(false),
                    ),
                    (
                        !self.opening,
                        "Open project…     Ctrl+Shift+O",
                        Action::OpenDialog(true),
                    ),
                    (loaded, "Create project…     Ctrl+N", Action::NewProject),
                    (project, "Save workspace     Ctrl+S", Action::Save),
                    (project, "Export annotations…", Action::Export),
                    (function, "Export pseudocode…", Action::ExportPseudocode),
                    (loaded || project, "Close image", Action::Close),
                ] {
                    command(ui, enabled, label, action, &mut self.actions);
                }
                ui.separator();
                ui.menu_button("Recent files", |ui| {
                    if self.recent.is_empty() {
                        ui.add_enabled(false, egui::Label::new("No recent files"));
                    }
                    for path in &self.recent {
                        command(
                            ui,
                            true,
                            &path.to_string_lossy(),
                            Action::Open(path.clone()),
                            &mut self.actions,
                        );
                    }
                });
                if ui.button("Exit").clicked() {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
            root_menu(ui, "Edit", egui::Key::E, |ui| {
                command(
                    ui,
                    function && project,
                    "Rename function…     F2",
                    Action::Rename,
                    &mut self.actions,
                );
                command(
                    ui,
                    project && self.location.address.is_some(),
                    "Edit comment…",
                    Action::Show(Panel::Inspector),
                    &mut self.actions,
                );
                ui.separator();
                command(
                    ui,
                    project && loaded && !self.analyzing,
                    "Define function here",
                    Action::Manual(true),
                    &mut self.actions,
                );
                command(
                    ui,
                    manual && !self.analyzing,
                    "Remove manual function",
                    Action::Manual(false),
                    &mut self.actions,
                );
            });
            root_menu(ui, "Jump", egui::Key::J, |ui| {
                command(
                    ui,
                    loaded,
                    "Go to address or symbol…     Ctrl+G",
                    Action::Palette,
                    &mut self.actions,
                );
                command(
                    ui,
                    back,
                    "Back     Alt+Left",
                    Action::Back,
                    &mut self.actions,
                );
                command(
                    ui,
                    forward,
                    "Forward     Alt+Right",
                    Action::Forward,
                    &mut self.actions,
                );
                if let Some(address) = self.function().map(|f| f.address) {
                    command(
                        ui,
                        true,
                        "Function start",
                        Action::Navigate(self.address_location(address), true),
                        &mut self.actions,
                    );
                }
                command(
                    ui,
                    self.analysis.is_some(),
                    "Cross-references",
                    Action::Show(Panel::Xrefs),
                    &mut self.actions,
                );
            });
            root_menu(ui, "Search", egui::Key::S, |ui| {
                command(
                    ui,
                    loaded,
                    "Address, symbol or command…",
                    Action::Palette,
                    &mut self.actions,
                );
                command(
                    ui,
                    self.analysis.is_some(),
                    "Functions…",
                    Action::Show(Panel::Functions),
                    &mut self.actions,
                );
                command(
                    ui,
                    loaded,
                    "Strings…",
                    Action::Show(Panel::Strings),
                    &mut self.actions,
                );
                command(
                    ui,
                    loaded && !self.scanning,
                    "Rescan strings",
                    Action::Scan,
                    &mut self.actions,
                );
            });
            root_menu(ui, "View", egui::Key::V, |ui| {
                for panel in [
                    Panel::Disassembly,
                    Panel::Graph,
                    Panel::Hex,
                    Panel::Strings,
                    Panel::Xrefs,
                    Panel::Overview,
                ] {
                    command(
                        ui,
                        true,
                        panel.title(),
                        Action::Show(panel),
                        &mut self.actions,
                    );
                }
                ui.separator();
                command(
                    ui,
                    loaded && !self.analyzing && !self.opening,
                    "Analyze functions",
                    Action::Analyze,
                    &mut self.actions,
                );
                command(
                    ui,
                    self.analyzing || self.ir_loading.is_some() || self.decomp_loading.is_some(),
                    "Cancel analysis",
                    Action::Cancel,
                    &mut self.actions,
                );
            });
            root_menu(ui, "Debugger", egui::Key::D, |ui| {
                ui.add_enabled(false, egui::Label::new("No debugger backend implemented"));
            });
            root_menu(ui, "Options", egui::Key::O, |ui| {
                command(
                    ui,
                    true,
                    "Preferences…     Ctrl+,",
                    Action::Settings,
                    &mut self.actions,
                );
                ui.menu_button("Theme", |ui| {
                    ui.selectable_value(
                        &mut self.settings.theme,
                        crate::design::Theme::Classic,
                        "Classic light",
                    );
                    ui.selectable_value(
                        &mut self.settings.theme,
                        crate::design::Theme::Dark,
                        "Professional dark",
                    );
                });
            });
            root_menu(ui, "Windows", egui::Key::W, |ui| {
                for panel in Panel::ALL {
                    command(
                        ui,
                        true,
                        panel.title(),
                        Action::Show(panel),
                        &mut self.actions,
                    );
                }
                ui.separator();
                command(
                    ui,
                    true,
                    "Reset layout",
                    Action::ResetLayout,
                    &mut self.actions,
                );
            });
            root_menu(ui, "Help", egui::Key::H, |ui| {
                if ui.button("Keyboard shortcuts / About URA").clicked() {
                    self.about_open = true;
                    ui.close();
                }
            });
        });
        ui.separator();
        ui.horizontal(|ui| {
            ui.set_min_height(24.0);
            ui.image((self.icon.id(), egui::vec2(20.0, 20.0)));
            for (enabled, text, tip, action) in [
                (
                    !self.opening,
                    "Open",
                    "Open binary · Ctrl+O",
                    Action::OpenDialog(false),
                ),
                (
                    project,
                    "Save",
                    "Save project workspace · Ctrl+S",
                    Action::Save,
                ),
                (back, "←", "Back · Alt+Left", Action::Back),
                (forward, "→", "Forward · Alt+Right", Action::Forward),
                (
                    loaded,
                    "Go to",
                    "Address / symbol / offset · Ctrl+G",
                    Action::Palette,
                ),
                (
                    loaded && !self.analyzing,
                    "Analyze",
                    "Analyze functions and references",
                    Action::Analyze,
                ),
            ] {
                if ui
                    .add_enabled(enabled, egui::Button::new(text))
                    .on_hover_text(tip)
                    .clicked()
                {
                    self.actions.push(action);
                }
            }
            if (self.analyzing || self.ir_loading.is_some() || self.decomp_loading.is_some())
                && ui.small_button("Cancel").clicked()
            {
                self.actions.push(Action::Cancel);
            }
            ui.separator();
            for (panel, label) in [
                (Panel::Disassembly, "Linear"),
                (Panel::Graph, "Graph"),
                (Panel::Hex, "Hex"),
                (Panel::Xrefs, "Xrefs"),
            ] {
                if ui.selectable_label(self.active == panel, label).clicked() {
                    self.actions.push(Action::Show(panel));
                }
            }
            if let Some(info) = &self.info {
                ui.separator();
                ui.add(
                    egui::Label::new(RichText::new(&info.file_name).color(self.colors().muted))
                        .truncate(),
                );
            }
        });
        if let Some(error) = self.last_error.clone() {
            ui.horizontal_wrapped(|ui| {
                ui.colored_label(self.colors().error, error);
                if ui.small_button("Dismiss").clicked() {
                    self.last_error = None;
                }
            });
        }
    }
}
