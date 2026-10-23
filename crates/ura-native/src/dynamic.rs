//! Functional isolated execution/replay controls. Service work stays off paint.
use crate::app::Workspace;
use eframe::egui;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};
use ura_service::{PathPolicy, dynamic::DynamicService};
struct Reply {
    key: &'static str,
    result: Result<Value, String>,
    preview: Vec<String>,
}
pub struct DynamicUi {
    service: Arc<Mutex<DynamicService>>,
    receiver: Option<mpsc::Receiver<Reply>>,
    pub busy: bool,
    pub replay_mode: bool,
    pub path: String,
    pub entry: String,
    pub code: String,
    pub registers: String,
    pub mappings: String,
    pub bits: u8,
    pub processor: Option<ura_core::processor::Processor>,
    pub raw: bool,
    pub steps: u64,
    pub until: String,
    pub session: String,
    pub state: Value,
    changed_registers: BTreeSet<String>,
    pub result: Value,
    history: Value,
    pub preview: Vec<String>,
    pub error: Option<String>,
    pub memory_address: String,
    pub destination: String,
    pub snapshot: u64,
    pub image: String,
    pub image_path: String,
    pub other_image: String,
    pub replay: String,
    pub replay_path: String,
    pub replay_info: Value,
    pub replay_events: Value,
    pub replay_state: Value,
    pub replay_index: usize,
    pub replay_offset: usize,
    pub replay_thread: String,
    pub overlay_sha: String,
    pub overlay_blocks: BTreeMap<u64, u64>,
    pub overlay_edges: BTreeSet<(u64, u64)>,
    last_poll: Instant,
}
impl Default for DynamicUi {
    fn default() -> Self {
        Self {
            service: Arc::new(Mutex::new(
                DynamicService::new(PathPolicy::allow_all(), true).with_emulation(true),
            )),
            receiver: None,
            busy: false,
            replay_mode: false,
            path: String::new(),
            entry: "0x1000".into(),
            code: "B8 2A 00 00 00 C3".into(),
            registers: "{}".into(),
            mappings: "[]".into(),
            bits: 64,
            processor: None,
            raw: false,
            steps: 1000,
            until: String::new(),
            session: String::new(),
            state: Value::Null,
            changed_registers: BTreeSet::new(),
            result: Value::Null,
            history: Value::Null,
            preview: vec![],
            error: None,
            memory_address: "0x1000".into(),
            destination: String::new(),
            snapshot: 1,
            image: String::new(),
            image_path: String::new(),
            other_image: String::new(),
            replay: String::new(),
            replay_path: String::new(),
            replay_info: Value::Null,
            replay_events: Value::Null,
            replay_state: Value::Null,
            replay_index: 0,
            replay_offset: 0,
            replay_thread: String::new(),
            overlay_sha: String::new(),
            overlay_blocks: BTreeMap::new(),
            overlay_edges: BTreeSet::new(),
            last_poll: Instant::now(),
        }
    }
}
impl DynamicUi {
    fn launch(
        &mut self,
        key: &'static str,
        ctx: &egui::Context,
        job: impl FnOnce(&mut DynamicService) -> Result<Value, String> + Send + 'static,
    ) {
        if self.busy {
            return;
        }
        self.busy = true;
        self.error = None;
        let service = self.service.clone();
        let ctx = ctx.clone();
        let (tx, rx) = mpsc::sync_channel(1);
        self.receiver = Some(rx);
        std::thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                job(&mut service.lock().unwrap_or_else(|e| e.into_inner()))
            }))
            .unwrap_or_else(|_| {
                Err(
                    "Analysis worker failed; close this evidence session and inspect the source."
                        .into(),
                )
            });
            let preview = result
                .as_ref()
                .ok()
                .and_then(|v| serde_json::to_string_pretty(v).ok())
                .map(|s| {
                    s.chars()
                        .take(24000)
                        .collect::<String>()
                        .lines()
                        .map(str::to_string)
                        .take(1000)
                        .collect()
                })
                .unwrap_or_default();
            let _ = tx.send(Reply {
                key,
                result,
                preview,
            });
            ctx.request_repaint();
        });
    }
    pub fn request(&mut self, key: &'static str, mut value: Value, ctx: &egui::Context) {
        if value["operation"] == "emulation" && value["action"] != "create" {
            value["session"] = json!(self.session);
        }
        self.launch(key, ctx, move |s| s.rpc(value).map_err(|e| e.to_string()));
    }
    pub fn poll(&mut self, ctx: &egui::Context) {
        if let Some(reply) = self.receiver.as_ref().and_then(|r| r.try_recv().ok()) {
            self.receiver = None;
            self.busy = false;
            self.preview = reply.preview;
            match reply.result {
                Err(e) => self.error = Some(e),
                Ok(v) => {
                    match reply.key {
                        "create" => {
                            self.session = v["session"].as_str().unwrap_or("").into();
                            self.state = v.clone();
                        }
                        "state" => {
                            self.changed_registers = v["state"]["registers"]
                                .as_object()
                                .map(|m| {
                                    m.iter()
                                        .filter(|(k, value)| {
                                            self.state["state"]["registers"][*k] != **value
                                        })
                                        .map(|(k, _)| k.clone())
                                        .collect()
                                })
                                .unwrap_or_default();
                            self.state = v.clone();
                        }
                        "close" => {
                            self.session.clear();
                            self.state = Value::Null;
                        }
                        "imageClose" => self.image.clear(),
                        "replayClose" => {
                            self.replay.clear();
                            self.replay_state = Value::Null;
                            self.replay_events = Value::Null;
                            self.overlay_sha.clear();
                            self.overlay_blocks.clear();
                            self.overlay_edges.clear();
                        }
                        "snapshot" => self.snapshot = v["id"].as_u64().unwrap_or(1),
                        "image" => self.image = v["handle"].as_str().unwrap_or("").into(),
                        "replayOpen" => {
                            self.replay = v["handle"].as_str().unwrap_or("").into();
                            self.replay_info = v["info"].clone();
                            self.replay_index = 0;
                            self.replay_offset = 0;
                            self.replay_state = Value::Null;
                            self.replay_events = Value::Null;
                            self.overlay_sha.clear();
                            self.overlay_blocks.clear();
                            self.overlay_edges.clear();
                        }
                        "history" => self.history = v.clone(),
                        "replayEvents" => self.replay_events = v.clone(),
                        "replayState" => self.replay_state = v.clone(),
                        "overlay" => {
                            self.overlay_sha = v["imageSha256"].as_str().unwrap_or("").into();
                            self.overlay_blocks = v["blockInstructionObservations"]
                                .as_object()
                                .map(|m| {
                                    m.iter()
                                        .filter_map(|(k, v)| {
                                            Some((ura_core::parse_address(k).ok()?, v.as_u64()?))
                                        })
                                        .collect()
                                })
                                .unwrap_or_default();
                            self.overlay_edges = v["transitions"]
                                .as_array()
                                .map(|a| {
                                    a.iter()
                                        .filter_map(|v| {
                                            Some((
                                                ura_core::parse_address(v["sourceBlock"].as_str()?)
                                                    .ok()?,
                                                ura_core::parse_address(
                                                    v["destinationBlock"].as_str()?,
                                                )
                                                .ok()?,
                                            ))
                                        })
                                        .collect()
                                })
                                .unwrap_or_default();
                        }
                        _ => {}
                    }
                    self.result = v;
                }
            }
        }
        if !self.busy
            && self.state["busy"] == true
            && self.last_poll.elapsed() > Duration::from_millis(40)
        {
            self.last_poll = Instant::now();
            self.request(
                "state",
                json!({"operation":"emulation","action":"status"}),
                ctx,
            );
        }
        if self.busy || self.state["busy"] == true {
            ctx.request_repaint_after(Duration::from_millis(40));
        }
    }
    fn button(&mut self, ui: &mut egui::Ui, label: &str, key: &'static str, value: Value) {
        if ui
            .add_enabled(
                !self.busy
                    && !(key == "image" && !self.image.is_empty())
                    && !(key == "replayOpen" && !self.replay.is_empty()),
                egui::Button::new(label),
            )
            .clicked()
        {
            self.request(key, value, ui.ctx());
        }
    }
    fn preview(&self, ui: &mut egui::Ui) {
        if let Some(e) = &self.error {
            ui.colored_label(egui::Color32::LIGHT_RED, e);
        }
        ui.label(
            "Bounded result preview (up to 24,000 characters). Addresses retain their source mode.",
        );
        egui::ScrollArea::both()
            .id_salt("dynamic-result")
            .max_height(280.0)
            .show_rows(ui, 16.0, self.preview.len(), |ui, r| {
                for line in &self.preview[r] {
                    ui.monospace(line);
                }
            });
    }
    fn emulator_panel(&mut self, ui: &mut egui::Ui) {
        ui.label("Isolated scalar CPU · no Windows program or host API execution");
        ui.horizontal(|ui| {
            ui.label("Code image (optional)");
            ui.text_edit_singleline(&mut self.path);
            ui.checkbox(&mut self.raw, "Raw file");
        });
        ui.horizontal(|ui| {
            ui.label("Entry");
            ui.text_edit_singleline(&mut self.entry);
            egui::ComboBox::from_id_salt("emulation-processor")
                .selected_text(
                    self.processor
                        .map_or("Automatic (native file); x64 raw", |p| p.name()),
                )
                .show_ui(ui, |ui| {
                    ui.selectable_value(
                        &mut self.processor,
                        None,
                        "Automatic (native file); x64 raw",
                    );
                    for p in [
                        ura_core::processor::Processor::X86,
                        ura_core::processor::Processor::X86_64,
                        ura_core::processor::Processor::Aarch64,
                        ura_core::processor::Processor::Arm,
                        ura_core::processor::Processor::Thumb,
                        ura_core::processor::Processor::Riscv32,
                        ura_core::processor::Processor::Riscv64,
                    ] {
                        ui.selectable_value(&mut self.processor, Some(p), p.name());
                    }
                });
            self.bits = self.processor.map_or(64, |p| p.bits());
        });
        ui.collapsing("Initial state", |ui| {
            ui.label("Raw code bytes when no image path is selected");
            ui.text_edit_multiline(&mut self.code);
            ui.label("Initial root registers/flags (JSON, for example {\"rcx\":\"0x2\"})");
            ui.text_edit_multiline(&mut self.registers);
            ui.label("Additional virtual memory mappings (JSON array)");
            ui.text_edit_multiline(&mut self.mappings);
        });
        if ui
            .add_enabled(
                !self.busy && self.session.is_empty(),
                egui::Button::new("Create emulation session"),
            )
            .clicked()
        {
            let result = (|| -> Result<Value, String> {
                let registers: Value =
                    serde_json::from_str(&self.registers).map_err(|e| e.to_string())?;
                let mut mappings: Vec<Value> =
                    serde_json::from_str(&self.mappings).map_err(|e| e.to_string())?;
                if self.path.is_empty() {
                    let bytes =
                        ura_core::patch::parse_hex(&self.code).map_err(|e| e.to_string())?;
                    mappings.push(json!({"base":self.entry,"size":bytes.len(),"bytes":bytes,"permissions":{"read":true,"write":false,"execute":true}}));
                }
                let mut v = json!({"operation":"emulation","action":"create","entry":self.entry,"config":{"bitness":self.bits,"processor":self.processor,"registers":registers,"mappings":mappings},"bitness":self.bits});
                if !self.path.is_empty() {
                    v["path"] = json!(self.path);
                    v["raw"] = json!(self.raw);
                    if self.raw {
                        v["base"] = json!(self.entry);
                    }
                }
                Ok(v)
            })();
            match result {
                Ok(v) => self.request("create", v, ui.ctx()),
                Err(e) => self.error = Some(e),
            }
        }
        if !self.session.is_empty() {
            ui.label(format!(
                "{} · {} · {} instructions · {}",
                self.session,
                self.state["state"]["status"],
                self.state["state"]["instructions"],
                self.state["state"]["stopReason"]
            ));
            ui.horizontal_wrapped(|ui| {
                ui.label("Instruction limit");
                ui.add(egui::DragValue::new(&mut self.steps).range(1..=1000000));
                ui.label("Run until (optional)");
                ui.text_edit_singleline(&mut self.until);
            });
            ui.horizontal_wrapped(|ui| {
                self.button(
                    ui,
                    "Step",
                    "state",
                    json!({"operation":"emulation","action":"step"}),
                );
                let mut v = json!({"operation":"emulation","action":"run","steps":self.steps});
                if !self.until.is_empty() {
                    v["until"] = json!(self.until);
                }
                self.button(ui, "Run bounded", "state", v);
                self.button(
                    ui,
                    "Stop",
                    "state",
                    json!({"operation":"emulation","action":"stop"}),
                );
                self.button(
                    ui,
                    "Reset initial state",
                    "state",
                    json!({"operation":"emulation","action":"reset"}),
                );
                if ui
                    .add_enabled(!self.busy, egui::Button::new("Close session"))
                    .clicked()
                {
                    self.request(
                        "close",
                        json!({"operation":"emulation","action":"close"}),
                        ui.ctx(),
                    );
                }
            });
            ui.collapsing("Emulated registers and arithmetic flags", |ui| {
                if let Some(regs) = self.state["state"]["registers"].as_object() {
                    egui::Grid::new("emulated-registers")
                        .num_columns(4)
                        .show(ui, |ui| {
                            for (i, (k, v)) in regs.iter().enumerate() {
                                ui.colored_label(
                                    if self.changed_registers.contains(k) {
                                        egui::Color32::GOLD
                                    } else {
                                        ui.visuals().text_color()
                                    },
                                    k,
                                );
                                ui.monospace(v.as_str().unwrap_or("Unavailable"));
                                if i % 2 == 1 {
                                    ui.end_row();
                                }
                            }
                        });
                }
                ui.label(format!(
                    "Flags: {} · known mask {}",
                    self.state["state"]["flagsValue"], self.state["state"]["flagsKnownMask"]
                ));
            });
            ui.horizontal_wrapped(|ui| {
                self.button(
                    ui,
                    "Save state",
                    "snapshot",
                    json!({"operation":"emulation","action":"snapshot"}),
                );
                ui.add(egui::DragValue::new(&mut self.snapshot));
                self.button(
                    ui,
                    "Restore saved state",
                    "state",
                    json!({"operation":"emulation","action":"restore","id":self.snapshot}),
                );
                self.button(
                    ui,
                    "Remove saved state",
                    "result",
                    json!({"operation":"emulation","action":"removeSnapshot","id":self.snapshot}),
                );
            });
            ui.horizontal_wrapped(|ui|{ui.label("Virtual address");ui.text_edit_singleline(&mut self.memory_address);self.button(ui,"Read virtual bytes","result",json!({"operation":"emulation","action":"memory","address":self.memory_address,"length":256}));self.button(ui,"Set breakpoint","result",json!({"operation":"emulation","action":"breakpoint","address":self.memory_address,"enabled":true}));self.button(ui,"Remove breakpoint","result",json!({"operation":"emulation","action":"breakpoint","address":self.memory_address,"enabled":false}));});
            ui.horizontal_wrapped(|ui| {
                self.button(
                    ui,
                    "Read execution history",
                    "history",
                    json!({"operation":"emulation","action":"trace","limit":128}),
                );
                self.button(
                    ui,
                    "Copy virtual memory to analysis image",
                    "image",
                    json!({"operation":"emulation","action":"memoryImage"}),
                );
            });
            let events = self.history["events"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            ui.collapsing("Emulated instruction history", |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("emulation-events")
                    .max_height(180.0)
                    .show_rows(ui, 18.0, events.len(), |ui, rows| {
                        for e in &events[rows] {
                            if ui
                                .selectable_label(
                                    false,
                                    format!(
                                        "{}: {} → {}",
                                        e["sequence"], e["address"], e["nextAddress"]
                                    ),
                                )
                                .clicked()
                            {
                                self.memory_address = e["address"].as_str().unwrap_or("0x0").into();
                            }
                        }
                    });
            });
            self.button(ui,"Decode selected virtual instruction","result",json!({"operation":"emulation","action":"disassembly","address":self.memory_address}));
            ui.horizontal(|ui|{ui.label("New trace export file");ui.text_edit_singleline(&mut self.destination);if !self.destination.is_empty(){self.button(ui,"Export emulation history","result",json!({"operation":"emulation","action":"exportTrace","destination":self.destination}));}});
        }
        ui.collapsing("Memory image analysis",|ui|{
            ui.label("Open an exported snapshot or memory-image bundle. Missing bytes stay unavailable.");
            ui.horizontal(|ui|{ui.text_edit_singleline(&mut self.image_path);self.button(ui,"Open captured image","image",json!({"operation":"image","action":"open","path":self.image_path,"bitness":self.bits}));});
            if !self.image.is_empty(){ui.label(format!("Selected image: {}",self.image));ui.horizontal_wrapped(|ui|{self.button(ui,"Image information","result",json!({"operation":"image","action":"info","handle":self.image}));self.button(ui,"Hex bytes","result",json!({"operation":"image","action":"memory","handle":self.image,"address":self.memory_address,"length":256}));self.button(ui,"Disassemble known bytes","result",json!({"operation":"image","action":"disassembly","handle":self.image,"address":self.memory_address,"length":64}));self.button(ui,"Analyze CFG, IR and pseudocode","result",json!({"operation":"image","action":"analyze","handle":self.image,"entry":self.entry}));});ui.horizontal(|ui|{ui.label("Compare image handle");ui.text_edit_singleline(&mut self.other_image);self.button(ui,"Compare known bytes","result",json!({"operation":"image","action":"compare","handle":self.image,"other":self.other_image,"address":self.memory_address,"length":256}));});ui.horizontal(|ui|{ui.label("New bundle file");ui.text_edit_singleline(&mut self.destination);self.button(ui,"Export image bundle","result",json!({"operation":"image","action":"export","handle":self.image,"destination":self.destination}));});}
        });
        self.preview(ui);
    }
    fn replay_panel(&mut self, ui: &mut egui::Ui) {
        ui.label("Replay recorded events · browsing does not execute the original program");
        ui.horizontal(|ui| {
            ui.text_edit_singleline(&mut self.replay_path);
            self.button(
                ui,
                "Load recorded trace",
                "replayOpen",
                json!({"operation":"replay","action":"open","path":self.replay_path}),
            );
        });
        if !self.replay.is_empty() {
            self.button(
                ui,
                "Close recorded trace",
                "replayClose",
                json!({"operation":"replay","action":"close","handle":self.replay}),
            );
            let total = self.replay_info["events"].as_u64().unwrap_or(0) as usize;
            ui.label(format!(
                "{} · {} source · {} events · historical memory unavailable",
                self.replay, self.replay_info["sourceMode"], total
            ));
            ui.horizontal_wrapped(|ui|{ui.label("Event index");ui.add(egui::DragValue::new(&mut self.replay_index).range(0..=total.saturating_sub(1)));if ui.button("Previous recorded event").clicked(){self.replay_index=self.replay_index.saturating_sub(1);}
if ui.button("Next recorded event").clicked(){self.replay_index=(self.replay_index+1).min(total.saturating_sub(1));}ui.label("Thread (optional)");ui.text_edit_singleline(&mut self.replay_thread);let mut v=json!({"operation":"replay","action":"state","handle":self.replay,"index":self.replay_index});if let Ok(t)=self.replay_thread.parse::<u32>(){v["thread"]=json!(t);}self.button(ui,"Inspect captured state","replayState",v);});
            ui.horizontal(|ui|{ui.label("Page offset");ui.add(egui::DragValue::new(&mut self.replay_offset).range(0..=total));let mut v=json!({"operation":"replay","action":"events","handle":self.replay,"offset":self.replay_offset,"limit":128});if let Ok(t)=self.replay_thread.parse::<u32>(){v["thread"]=json!(t);}self.button(ui,"Read replay page","replayEvents",v);});
            let rows = self.replay_events["events"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            egui::ScrollArea::both().id_salt("replay-rows").max_height(220.0).show_rows(ui,18.0,rows.len(),|ui,r|{for row in &rows[r]{let event=&row["event"];let label=format!("{} · T{} · {} · {}",row["index"],event["thread"],event["address"],event["kind"]);if ui.selectable_label(false,label).clicked(){self.replay_index=row["index"].as_u64().unwrap_or(0) as usize;self.request("replayState",json!({"operation":"replay","action":"state","handle":self.replay,"index":self.replay_index}),ui.ctx());}}});
            if !self.replay_state.is_null() {
                ui.label(format!(
                    "Register sample from sequence {} · complete: {} · {}",
                    self.replay_state["capturedAtSequence"],
                    self.replay_state["registersComplete"],
                    self.replay_state["sampleTiming"]
                ));
                if let Some(regs) = self.replay_state["registers"].as_object() {
                    egui::Grid::new("replay-registers").show(ui, |ui| {
                        for (k, v) in regs {
                            ui.monospace(k);
                            ui.monospace(v.as_str().unwrap_or("Unavailable"));
                            ui.end_row();
                        }
                    });
                }
            }
        }
        self.preview(ui);
    }
}
impl Workspace {
    pub(crate) fn emulation_view(&mut self, ui: &mut egui::Ui) {
        if ui.button("Use currently opened original file").clicked()
            && let Some(binary) = &self.binary
        {
            self.dynamic.path = binary.path().display().to_string();
            self.dynamic.entry = ura_core::format_address(
                self.location
                    .address
                    .or(binary.analysis().entry_point)
                    .unwrap_or(0),
            );
        }
        if ui
            .add_enabled(
                !self.dynamic.busy && self.dynamic.image.is_empty() && self.binary.is_some(),
                egui::Button::new("Copy opened effective file bytes to analysis image"),
            )
            .clicked()
        {
            let binary = self.binary.clone().unwrap();
            let patched = self
                .patches
                .as_ref()
                .is_some_and(|p| p.changed_bytes() != 0);
            self.dynamic.launch("image",ui.ctx(),move|s|{let mut image=ura_core::dynamic::image::Image::from_binary(&binary).map_err(|e|e.to_string())?;image.provenance=format!("Opened effective file bytes; active patch overlay: {patched}; preferred virtual addresses; no relocation or OS loader");s.insert_image(image).map_err(|e|e.to_string())});
        }
        egui::ScrollArea::vertical()
            .id_salt("emulation-panel")
            .show(ui, |ui| self.dynamic.emulator_panel(ui));
    }
    pub(crate) fn replay_view(&mut self, ui: &mut egui::Ui) {
        self.dynamic.replay_panel(ui);
        if !self.dynamic.replay.is_empty() {
            if ui
                .add_enabled(
                    !self.dynamic.busy && self.analysis.is_some() && self.info.is_some(),
                    egui::Button::new("Show matching recorded samples on static CFG"),
                )
                .clicked()
            {
                if self
                    .patches
                    .as_ref()
                    .is_some_and(|p| p.changed_bytes() != 0)
                {
                    self.dynamic.error=Some("The active file has patches; open the matching original image for trace mapping.".into());
                    return;
                }
                let analysis = self.analysis.clone().unwrap();
                let info = self.info.clone().unwrap();
                let replay = self.dynamic.replay.clone();
                let base = self
                    .binary
                    .as_ref()
                    .map(|b| b.analysis().image_base)
                    .unwrap_or(0);
                self.dynamic.launch("overlay", ui.ctx(), move |s| {
                    s.overlay(&replay, &analysis, &info.sha256, base)
                        .map_err(|e| e.to_string())
                });
            }
            if ui
                .button("Navigate selected recorded address in matching image")
                .clicked()
            {
                let target = self.dynamic.replay_events["events"]
                    .as_array()
                    .and_then(|a| {
                        a.iter()
                            .find(|r| r["index"].as_u64() == Some(self.dynamic.replay_index as u64))
                    })
                    .and_then(|r| {
                        let m = &r["event"]["module"];
                        if self.info.as_ref()?.sha256 != m["sha256"].as_str()? {
                            return None;
                        }
                        let rva = ura_core::parse_address(m["rva"].as_str()?).ok()?;
                        self.binary.as_ref()?.analysis().image_base.checked_add(rva)
                    });
                if self
                    .patches
                    .as_ref()
                    .is_some_and(|p| p.changed_bytes() != 0)
                {
                    self.dynamic.error =
                        Some("Open the matching original image before trace navigation.".into());
                } else if let Some(address) = target {
                    self.navigate_address(address);
                } else {
                    self.dynamic.error = Some(
                        "A matching captured module identity and loaded replay page are required."
                            .into(),
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn settle(ui: &mut DynamicUi, ctx: &egui::Context) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            ui.poll(ctx);
            if !ui.busy && ui.state["busy"] != true {
                break;
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(ui.error.is_none(), "{:?}", ui.error);
    }
    #[test]
    fn headless_controls_execute_and_analyze_real_virtual_state() {
        let ctx = egui::Context::default();
        let mut ui = DynamicUi::default();
        ui.request("create",json!({"operation":"emulation","action":"create","config":{"mappings":[{"base":"0x1000","bytes":[184,42,0,0,0,195],"size":6,"permissions":{"read":true,"write":false,"execute":true}}]}}),&ctx);
        settle(&mut ui, &ctx);
        assert!(!ui.session.is_empty());
        ui.request(
            "state",
            json!({"operation":"emulation","action":"run","steps":10}),
            &ctx,
        );
        settle(&mut ui, &ctx);
        assert_eq!(ui.state["state"]["registers"]["rax"], "0x2A");
        assert!(ui.changed_registers.contains("rax"));
        ui.request(
            "image",
            json!({"operation":"emulation","action":"memoryImage"}),
            &ctx,
        );
        settle(&mut ui, &ctx);
        assert!(!ui.image.is_empty());
        ui.request(
            "imageClose",
            json!({"operation":"image","action":"close","handle":ui.image}),
            &ctx,
        );
        settle(&mut ui, &ctx);
        assert!(ui.image.is_empty());
        ui.request(
            "close",
            json!({"operation":"emulation","action":"close"}),
            &ctx,
        );
        settle(&mut ui, &ctx);
        assert!(ui.session.is_empty());
    }
    #[test]
    fn worker_panic_is_reported_and_all_dynamic_views_paint_headlessly() {
        let ctx = egui::Context::default();
        let mut ui = DynamicUi::default();
        ui.launch("result", &ctx, |_| panic!("controlled worker failure"));
        let deadline = Instant::now() + Duration::from_secs(5);
        while ui.busy {
            ui.poll(&ctx);
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(ui.error.as_deref().unwrap().contains("worker failed"));
        let mut output = ctx.run_ui(Default::default(), |egui_ui| {
            ui.emulator_panel(egui_ui);
            ui.replay_panel(egui_ui);
        });
        output.textures_delta.clear();
        assert!(!output.shapes.is_empty());
    }
}
