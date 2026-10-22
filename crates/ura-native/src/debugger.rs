//! Native projections of the shared debugger service; OS calls stay off paint.
use crate::app::{Action, Panel, Workspace};
use eframe::egui::{self, RichText};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex, mpsc},
    time::Duration,
};
use ura_debugger::{Snapshot, State};
use ura_service::{DebugPermissions, DebugService, PathPolicy};

type SharedDebugService = Arc<Mutex<DebugService>>;
type PendingDebugService = Arc<Mutex<Option<SharedDebugService>>>;
type Reply = (String, std::result::Result<Value, String>, Snapshot);
#[derive(Default)]
pub struct DebugUi {
    pending_service: Option<PendingDebugService>,
    service: Option<SharedDebugService>,
    receiver: Option<mpsc::Receiver<Reply>>,
    pub snapshot: Snapshot,
    pub path: String,
    args: String,
    cwd: String,
    pid: String,
    pub error: Option<String>,
    pub busy: bool,
    allow_terminate_attached: bool,
    memory_address: String,
    breakpoint_address: String,
    inspection: Value,
    last_stop: String,
    previous_registers: std::collections::BTreeMap<String, String>,
    captured_registers: Option<ura_debugger::Registers>,
}
impl DebugUi {
    fn start(&mut self, attach: bool, ctx: &egui::Context) {
        if self.busy || self.snapshot.state.active() {
            return;
        }
        let path = PathBuf::from(&self.path);
        let pid = self.pid.parse::<u32>().ok();
        if attach && pid.is_none() {
            self.error = Some("Enter an explicit PID and its executable path.".into());
            return;
        }
        let arguments = self.args.lines().map(str::to_owned).collect::<Vec<_>>();
        let cwd = (!self.cwd.trim().is_empty()).then(|| PathBuf::from(&self.cwd));
        let request = if attach {
            json!({"operation":"attach","pid":pid,"executable":path})
        } else {
            json!({"operation":"launch","executable":path,"arguments":arguments,"workingDirectory":cwd})
        };
        let mut roots = vec![
            path.parent()
                .unwrap_or(std::path::Path::new("."))
                .to_path_buf(),
        ];
        if let Some(cwd) = cwd {
            roots.push(cwd);
        }
        let permissions = DebugPermissions {
            launch: !attach,
            attach,
            terminate_attached: self.allow_terminate_attached,
            targets: vec![path],
            attach_pids: pid.into_iter().collect(),
        };
        let (sender, receiver) = mpsc::sync_channel(1);
        self.receiver = Some(receiver);
        self.busy = true;
        self.error = None;
        let shared = Arc::new(Mutex::new(None));
        let out = shared.clone();
        let repaint = ctx.clone();
        std::thread::spawn(move || {
            let result = (|| {
                let policy = PathPolicy::new(roots).map_err(|e| e.to_string())?;
                let mut service = DebugService::new(policy, permissions)
                    .map_err(|e| e.to_string())?
                    .with_project_writes(true);
                let result = service.rpc(request).map_err(|e| e.to_string());
                let snapshot = service.snapshot();
                *out.lock().unwrap() = Some(Arc::new(Mutex::new(service)));
                Ok((result, snapshot))
            })();
            let reply = match result {
                Ok((result, snapshot)) => ("start".into(), result, snapshot),
                Err(e) => ("start".into(), Err(e), Snapshot::default()),
            };
            let _ = sender.send(reply);
            repaint.request_repaint();
        });
        // A tiny setup receiver transfers the service without blocking the render thread.
        self.pending_service = Some(shared);
    }
    fn request(&mut self, kind: &str, mut request: Value, ctx: &egui::Context) {
        if self.busy {
            return;
        }
        let Some(service) = self.service.clone() else {
            return;
        };
        request["session"] = json!(self.snapshot.session);
        let (sender, receiver) = mpsc::sync_channel(1);
        self.receiver = Some(receiver);
        self.busy = true;
        let kind = kind.to_owned();
        let repaint = ctx.clone();
        std::thread::spawn(move || {
            let mut service = service.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(project) = request["project"].as_str()
                && let Err(e) = service.grant_project(std::path::Path::new(project))
            {
                let snapshot = service.snapshot();
                let _ = sender.send((kind, Err(e.to_string()), snapshot));
                repaint.request_repaint();
                return;
            }
            let result = if kind == "inspect" {
                let snapshot = service.snapshot();
                let session = snapshot.session.clone();
                let ip = snapshot
                    .registers
                    .as_ref()
                    .and_then(|r| r.values.get("rip"))
                    .cloned();
                let sp = snapshot
                    .registers
                    .as_ref()
                    .and_then(|r| r.values.get("rsp"))
                    .cloned();
                let mut values = json!({});
                for (key, rpc) in [
                    (
                        "runtime",
                        json!({"operation":"disassembly","session":session,"address":ip,"count":32}),
                    ),
                    (
                        "memory",
                        json!({"operation":"readMemory","session":session,"address":sp,"length":256}),
                    ),
                    (
                        "stack",
                        json!({"operation":"callStack","session":session,"limit":32}),
                    ),
                ] {
                    values[key] = service
                        .rpc(rpc)
                        .unwrap_or_else(|e| json!({"error":e.to_string()}));
                }
                Ok(values)
            } else {
                service.rpc(request).map_err(|e| e.to_string())
            };
            let snapshot = service.snapshot();
            let _ = sender.send((kind, result, snapshot));
            repaint.request_repaint();
        });
    }
    pub fn poll(&mut self, ctx: &egui::Context) {
        if let Some(receiver) = &self.receiver
            && let Ok((kind, result, snapshot)) = receiver.try_recv()
        {
            self.receiver = None;
            self.busy = false;
            if let Some(pending) = self.pending_service.take() {
                self.service = pending.lock().unwrap().take();
            }
            match result {
                Ok(value) => {
                    if !self.inspection.is_object() {
                        self.inspection = json!({});
                    }
                    if kind == "inspect" {
                        self.inspection = value;
                    } else if kind == "memory" {
                        self.inspection["memory"] = value;
                    } else if kind == "runtime" {
                        self.inspection["runtime"] = value;
                    }
                    self.error = None;
                }
                Err(e) => self.error = Some(e),
            }
            self.snapshot = snapshot;
        }
        if let Some(service) = &self.service
            && let Ok(service) = service.try_lock()
        {
            self.snapshot = service.snapshot();
        }
        if self.snapshot.state == State::Paused {
            let key = format!(
                "{:?}/{:?}/{:?}",
                self.snapshot.session,
                self.snapshot.selected_thread,
                self.snapshot.events.last().map(|e| e.sequence)
            );
            if key != self.last_stop && !self.busy {
                self.previous_registers = self
                    .captured_registers
                    .as_ref()
                    .filter(|r| Some(r.thread) == self.snapshot.selected_thread)
                    .map(|r| r.values.clone())
                    .unwrap_or_default();
                self.captured_registers = self.snapshot.registers.clone();
                self.last_stop = key;
                self.inspection = json!({});
                self.request("inspect", json!({}), ctx);
            }
        } else {
            self.inspection = Value::Null;
        }
        if (self.snapshot.state.active() && self.snapshot.state != State::Paused) || self.busy {
            ctx.request_repaint_after(Duration::from_millis(150));
        }
    }
    fn controls(&mut self, ui: &mut egui::Ui) {
        ui.label("Explicit local execution / attachment — native Windows x64");
        ui.horizontal(|ui| {
            ui.label("Executable");
            ui.text_edit_singleline(&mut self.path);
        });
        ui.label("Arguments: one argument per line");
        ui.add(egui::TextEdit::multiline(&mut self.args).desired_rows(2));
        ui.horizontal(|ui| {
            ui.label("Working directory (optional)");
            ui.text_edit_singleline(&mut self.cwd);
        });
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    !self.busy && !self.snapshot.state.active() && !self.path.is_empty(),
                    egui::Button::new("Launch under debugger"),
                )
                .clicked()
            {
                self.start(false, ui.ctx());
            }
            ui.label("PID");
            ui.add(egui::TextEdit::singleline(&mut self.pid).desired_width(70.));
            if ui
                .add_enabled(
                    !self.busy && !self.snapshot.state.active() && !self.path.is_empty(),
                    egui::Button::new("Attach selected PID"),
                )
                .clicked()
            {
                self.start(true, ui.ctx());
            }
        });
        ui.add_enabled_ui(!self.snapshot.state.active(), |ui| {
            ui.checkbox(
                &mut self.allow_terminate_attached,
                "Authorize terminating the selected attached target",
            );
        });
        self.execution_controls(ui);
    }
    pub fn execution_controls(&mut self, ui: &mut egui::Ui) {
        let state = self.snapshot.state;
        let available = !self.busy && self.snapshot.reason.as_deref() != Some("cleanupPending");
        let paused = state == State::Paused && available;
        let execution = paused && self.snapshot.reason.as_deref() != Some("authorizationFailed");
        let running = matches!(state, State::Running | State::Stepping) && available;
        ui.horizontal_wrapped(|ui| {
            for (label, enabled, operation, extra) in [
                ("Continue", execution, "continue", false),
                ("Pause", running, "pause", false),
                ("Step into", execution, "step", false),
                ("Step over", execution, "step", true),
                ("Detach", paused, "detach", false),
                (
                    "Terminate",
                    state.active()
                        && !self.busy
                        && (!self.snapshot.attached || self.allow_terminate_attached),
                    "terminate",
                    false,
                ),
            ] {
                if ui.add_enabled(enabled, egui::Button::new(label)).clicked() {
                    let mut value = json!({"operation":operation});
                    if operation == "step" {
                        value["over"] = json!(extra);
                    }
                    self.request("control", value, ui.ctx());
                }
            }
        });
        ui.label(format!(
            "{:?} · PID {:?} · {}",
            state,
            self.snapshot.pid,
            self.snapshot.reason.as_deref().unwrap_or("")
        ));
    }
}

impl Workspace {
    pub fn paused_static_ip(&self) -> Option<u64> {
        if self.debugger.snapshot.state != State::Paused {
            return None;
        }
        let ip = self
            .debugger
            .snapshot
            .registers
            .as_ref()?
            .values
            .get("rip")?;
        self.runtime_to_static(ura_core::parse_address(ip).ok()?)
    }
    pub fn runtime_evidence_banner(&mut self, ui: &mut egui::Ui) {
        if let Some(address) = self.paused_static_ip() {
            ui.horizontal(|ui| {
                ui.label(format!(
                    "Paused runtime IP maps to {} · observed state; analysis remains static",
                    ura_core::format_address(address)
                ));
                if ui.small_button("Follow paused IP").clicked() {
                    self.navigate_address(address);
                }
            });
        }
    }
    pub fn runtime_to_static(&self, runtime: u64) -> Option<u64> {
        let info = self.info.as_ref()?;
        if self
            .patches
            .as_ref()
            .is_some_and(|p| p.changed_bytes() != 0)
        {
            return None;
        }
        let module = self
            .debugger
            .snapshot
            .modules
            .iter()
            .find(|m| m.sha256.as_deref() == Some(&info.sha256))?;
        let base = ura_core::parse_address(&module.base).ok()?;
        let rva = runtime.checked_sub(base)?;
        if rva >= module.size {
            return None;
        }
        ura_core::parse_address(&info.image_base)
            .ok()?
            .checked_add(rva)
    }
    pub fn debugger_panel(&mut self, ui: &mut egui::Ui, panel: Panel) {
        let view = self.debugger.snapshot.clone();
        if panel == Panel::Debugger {
            if let Some(info) = &self.info
                && ui
                    .add_enabled(
                        !view.state.active() && !self.debugger.busy,
                        egui::Button::new("Use open image path"),
                    )
                    .clicked()
            {
                self.debugger.path = info.path.clone();
            }
            self.debugger.controls(ui);
        } else {
            ui.label(format!(
                "{:?} · session {} · runtime process state",
                view.state,
                view.session.as_deref().unwrap_or("none")
            ));
            if view.state != State::Paused
                && matches!(
                    panel,
                    Panel::Registers | Panel::DebugStack | Panel::Memory | Panel::Runtime
                )
            {
                ui.label("Pause the target to capture current runtime state.");
                return;
            }
            match panel {
                Panel::Registers => {
                    if let Some(registers) = &view.registers {
                        egui::Grid::new("debug-registers").striped(true).show(ui,|ui|{for(name,value)in &registers.values {
                    ui.label(name);let changed=self.debugger.previous_registers.get(name).is_some_and(|v|v!=value);
                    let text=RichText::new(value).monospace();if ui.selectable_label(false,if changed{text.color(self.colors().accent)}else{text}).clicked(){ui.ctx().copy_text(value.clone());}
                    if ui.small_button("View memory").clicked(){self.debugger.memory_address=value.clone();self.debugger.request("memory",json!({"operation":"readMemory","address":value,"length":256}),ui.ctx());self.actions.push(Action::Show(Panel::Memory));}
                    ui.end_row();}});
                    }
                }
                Panel::Threads => {
                    for thread in &view.threads {
                        if ui
                            .selectable_label(
                                view.selected_thread == Some(thread.id),
                                format!("{} · observed start {}", thread.id, thread.start_address),
                            )
                            .clicked()
                        {
                            self.debugger.request(
                                "registers",
                                json!({"operation":"registers","thread":thread.id}),
                                ui.ctx(),
                            );
                        }
                    }
                }
                Panel::Modules => {
                    egui::ScrollArea::both().show(ui, |ui| {
                        for module in &view.modules {
                            ui.monospace(format!(
                                "{} +0x{:X}  {}",
                                module.base,
                                module.size,
                                module.path.as_deref().unwrap_or("path unavailable")
                            ));
                        }
                    });
                }
                Panel::DebugEvents => {
                    egui::ScrollArea::both()
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            for event in &view.events {
                                ui.monospace(format!(
                                    "{}  T{}  {}  {}",
                                    event.sequence, event.thread, event.kind, event.message
                                ));
                            }
                            ui.label(format!("{} older events discarded", view.events_dropped));
                        });
                }
                Panel::Breakpoints => {
                    if let Some((project, _)) = &self.project {
                        let project = project.clone();
                        ui.horizontal(|ui|{for(label,action)in [("Save module/RVA definitions","save"),("Restore definitions for this image","restore")] {if ui.add_enabled(!self.debugger.busy&&view.state==State::Paused,egui::Button::new(label)).clicked(){self.debugger.request("breakpoint",json!({"operation":"breakpoints","action":action,"project":project}),ui.ctx());}}});
                    }
                    ui.horizontal(|ui|{ui.label("Runtime address (hex)");ui.text_edit_singleline(&mut self.debugger.breakpoint_address);if ui.add_enabled(!self.debugger.busy,egui::Button::new("Set software breakpoint")).clicked(){self.debugger.request("breakpoint",json!({"operation":"breakpoints","action":"set","address":self.debugger.breakpoint_address}),ui.ctx());}});
                    for point in &view.breakpoints {
                        if ui
                            .add_enabled(
                                !self.debugger.busy && view.state == State::Paused,
                                egui::Button::new(format!("View live {}", point.address)),
                            )
                            .clicked()
                        {
                            self.debugger.request("runtime",json!({"operation":"disassembly","address":point.address,"count":32}),ui.ctx());
                            self.actions.push(Action::Show(Panel::Runtime));
                        }
                        ui.horizontal(|ui|{ui.monospace(format!("#{} {} · {} · {} hits · byte {:02X}",point.id,point.address,point.owner,point.hits,point.original_byte));for(label,action)in [(if point.enabled{"Disable"}else{"Enable"},if point.enabled{"disable"}else{"enable"}),("Remove","remove")] {if ui.add_enabled(!self.debugger.busy&&view.state==State::Paused,egui::Button::new(label)).clicked(){self.debugger.request("breakpoint",json!({"operation":"breakpoints","action":action,"id":point.id}),ui.ctx());}}});
                    }
                }
                Panel::Memory => {
                    ui.horizontal(|ui|{ui.label("Runtime address");ui.text_edit_singleline(&mut self.debugger.memory_address);if ui.add_enabled(!self.debugger.busy,egui::Button::new("Read 256 bytes")).clicked(){self.debugger.request("memory",json!({"operation":"readMemory","address":self.debugger.memory_address,"length":256}),ui.ctx());}});
                    let memory = &self.debugger.inspection["memory"];
                    if let Some(bytes) = memory["bytes"].as_array() {
                        let base = memory["address"]
                            .as_str()
                            .and_then(|s| ura_core::parse_address(s).ok())
                            .unwrap_or(0);
                        egui::ScrollArea::both().show(ui, |ui| {
                            for (index, row) in bytes.chunks(16).enumerate() {
                                let data = row
                                    .iter()
                                    .map(|b| b.as_u64().unwrap_or(0) as u8)
                                    .collect::<Vec<_>>();
                                let hex = data
                                    .iter()
                                    .map(|b| format!("{b:02X}"))
                                    .collect::<Vec<_>>()
                                    .join(" ");
                                let ascii = data
                                    .iter()
                                    .map(|&b| if b.is_ascii_graphic() { b as char } else { '.' })
                                    .collect::<String>();
                                ui.monospace(format!(
                                    "{:016X}  {:47}  {}",
                                    base + index as u64 * 16,
                                    hex,
                                    ascii
                                ));
                            }
                        });
                    }
                    if memory["partial"] == true {
                        ui.label(format!("Partial read: {}", memory["error"]));
                    }
                }
                Panel::DebugStack => {
                    let mut navigate = None;
                    if let Some(frames) = self.debugger.inspection["stack"]["frames"].as_array() {
                        for frame in frames {
                            if ui
                                .selectable_label(
                                    false,
                                    format!(
                                        "{}  {}  {}  {}",
                                        frame["index"],
                                        frame["instructionPointer"],
                                        frame["module"],
                                        frame["symbol"].as_str().unwrap_or("unknown symbol")
                                    ),
                                )
                                .clicked()
                            {
                                navigate = frame["instructionPointer"]
                                    .as_str()
                                    .and_then(|s| ura_core::parse_address(s).ok());
                            }
                        }
                    }
                    ui.label("Windows unwind metadata; incomplete frames remain unknown.");
                    if let Some(address) = navigate {
                        self.follow_runtime(address);
                    }
                }
                Panel::Runtime => {
                    let mut navigate = None;
                    if let Some(instructions) =
                        self.debugger.inspection["runtime"]["instructions"].as_array()
                    {
                        for instruction in instructions {
                            let address = instruction["address"].as_str().unwrap_or("");
                            let ip = view
                                .registers
                                .as_ref()
                                .and_then(|r| r.values.get("rip"))
                                .is_some_and(|v| v.eq_ignore_ascii_case(address));
                            if ui
                                .selectable_label(
                                    ip,
                                    RichText::new(format!(
                                        "{}  {}  {}",
                                        address,
                                        instruction["bytes"].as_str().unwrap_or(""),
                                        instruction["text"].as_str().unwrap_or("")
                                    ))
                                    .monospace(),
                                )
                                .clicked()
                            {
                                navigate = ura_core::parse_address(address).ok();
                            }
                        }
                    }
                    ui.label("Live bytes include armed INT3; static pseudocode describes the matched file image.");
                    if let Some(address) = navigate {
                        self.follow_runtime(address);
                    }
                }
                _ => {}
            }
        }
        if let Some(error) = &self.debugger.error {
            ui.colored_label(self.colors().accent, error);
        }
        if self.debugger.busy {
            ui.label("Debugger request pending…");
        }
    }
    fn follow_runtime(&mut self, address: u64) {
        if let Some(address) = self.runtime_to_static(address) {
            self.navigate_address(address);
            self.actions.push(Action::Show(Panel::Disassembly));
        } else {
            self.debugger.error=Some("No identity-matched static mapping. Dirty file overlays must be reverted before runtime/static navigation.".into());
        }
    }
}

#[cfg(all(test, windows, target_arch = "x86_64"))]
#[path = "debugger_tests.rs"]
mod tests;
