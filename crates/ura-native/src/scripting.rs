//! Native console/plugin UI; interpreter startup, API calls and teardown stay off paint.
use crate::app::Workspace;
use eframe::egui;
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};
use ura_extensions::{ExecutionConfig, ExtensionHost};
struct Reply {
    key: &'static str,
    result: Result<Value, String>,
    host: Option<Arc<ExtensionHost>>,
}
pub struct ScriptUi {
    host: Option<Arc<ExtensionHost>>,
    receiver: Option<mpsc::Receiver<Reply>>,
    revision: Option<(u64, u64, u64)>,
    pub busy: bool,
    pub code: String,
    pub output: String,
    pub error: Option<String>,
    pub history: Vec<String>,
    history_index: usize,
    pub writes: bool,
    pub grants: String,
    pub registry: String,
    pub plugin_path: String,
    input_path: String,
    context_handle: String,
    context_kind: String,
    navigation: String,
    pub configuration: String,
    pub result: Value,
    pub inventory: Value,
    handle: String,
    session: String,
    job: String,
    last_poll: Instant,
    pub file: Option<PathBuf>,
    pub batch_request: String,
    pub refresh_project: bool,
}
impl Default for ScriptUi {
    fn default() -> Self {
        Self{host:None,receiver:None,revision:None,busy:false,code:"import ura\np = ura.current_project()\nfor f in p.functions(limit=16):\n    print(hex(f.address), f.name)".into(),output:String::new(),error:None,history:vec![],history_index:0,writes:false,grants:"project.read,analysis.read,ui.commands,events.subscribe,loader.register,processor.register".into(),registry:ExecutionConfig::default().registry.to_string_lossy().into_owned(),plugin_path:String::new(),input_path:String::new(),context_handle:String::new(),context_kind:String::new(),navigation:"0x0".into(),configuration:"{}".into(),result:Value::Null,inventory:Value::Null,handle:String::new(),session:String::new(),job:String::new(),last_poll:Instant::now(),file:None,batch_request:"{\"operation\":\"batch\",\"action\":\"status\",\"id\":\"batch-1\"}".into(),refresh_project:false}
    }
}
impl Drop for ScriptUi {
    fn drop(&mut self) {
        if let Some(host) = self.host.take() {
            host.request_shutdown();
            let _ = std::thread::spawn(move || drop(host));
        }
    }
}
impl ScriptUi {
    pub fn synchronize(&mut self, revision: (u64, u64, u64)) {
        if self.host.is_some() {
            self.revision = Some(revision);
        }
    }
    fn reset(&mut self) {
        if let Some(host) = self.host.take() {
            host.request_shutdown();
            let _ = std::thread::spawn(move || drop(host));
        }
        self.receiver = None;
        self.busy = false;
        self.session.clear();
        self.job.clear();
        self.revision = None;
        self.result = Value::Null;
        self.context_handle.clear();
        self.context_kind.clear();
        self.handle.clear();
        self.output.clear();
        self.refresh_project = false;
    }
    fn rpc(&mut self, key: &'static str, p: Value, ctx: &egui::Context) {
        if self.busy {
            return;
        }
        let Some(host) = self.host.clone() else {
            self.error = Some("Enable the trusted Python session first".into());
            return;
        };
        let (tx, rx) = mpsc::sync_channel(1);
        let ctx = ctx.clone();
        self.receiver = Some(rx);
        self.busy = true;
        self.error = None;
        std::thread::spawn(move || {
            let result = host.rpc(p);
            let _ = tx.send(Reply {
                key,
                result,
                host: None,
            });
            ctx.request_repaint();
        });
    }
    pub fn poll(&mut self, ctx: &egui::Context, revision: (u64, u64, u64)) {
        if self.revision.is_some_and(|r| r != revision) {
            self.reset();
            self.error =
                Some("Project changed; interpreter discarded. Enable a fresh session.".into());
        }
        let reply = self.receiver.as_ref().and_then(|r| r.try_recv().ok());
        if let Some(reply) = reply {
            self.busy = false;
            self.receiver = None;
            match reply.result {
                Err(e) => self.error = Some(e),
                Ok(v) => {
                    match reply.key {
                        "initialize" => {
                            self.handle = v["handle"].as_str().unwrap_or("").into();
                            self.session = v["session"].as_str().unwrap_or("").into();
                            self.host = reply.host;
                        }
                        "inventory" => self.inventory = v.clone(),
                        "run" => self.job = v["job"].as_str().unwrap_or("").into(),
                        "status" => {
                            self.output = format!(
                                "{}{}",
                                v["stdout"].as_str().unwrap_or(""),
                                v["stderr"].as_str().unwrap_or("")
                            );
                            if v["state"] != "running" {
                                self.job.clear();
                                self.error = v["error"].as_str().map(str::to_owned);
                                self.refresh_project = self.writes;
                                if v["sourcePlugin"].is_null() {
                                    self.rpc("forget",json!({"operation":"scripts","action":"forget","job":v["id"]}),ctx);
                                }
                            }
                        }
                        "accept" => {
                            if v["kind"] == "loader" {
                                self.context_handle = v["image"].as_str().unwrap_or("").into();
                                self.context_kind = "image".into();
                                self.navigation = v["entry"].as_str().unwrap_or("0x0").into();
                            } else if v["kind"] == "processor" {
                                self.context_handle = v["handle"].as_str().unwrap_or("").into();
                                self.context_kind = "processor".into();
                                self.navigation = v["entry"].as_str().unwrap_or("0x0").into();
                            }
                        }
                        _ => {}
                    }
                    if reply.key != "forget" {
                        self.result = v;
                    }
                }
            }
        }
        if !self.job.is_empty()
            && !self.busy
            && self.last_poll.elapsed() > Duration::from_millis(100)
        {
            self.last_poll = Instant::now();
            self.rpc(
                "status",
                json!({"operation":"scripts","action":"status","job":self.job}),
                ctx,
            );
        }
        if self.busy || !self.job.is_empty() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
}
impl Workspace {
    fn initialize_scripting(&mut self) {
        let snapshot = (
            self.binary.clone(),
            self.analysis.clone(),
            self.info.clone(),
        );
        let script = &mut self.scripting;
        script.reset();
        let mut config = ExecutionConfig {
            enabled: true,
            snippets: true,
            plugin_management: true,
            registry: PathBuf::from(&script.registry),
            capabilities: script
                .grants
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect(),
            ..Default::default()
        };
        if script.writes {
            config.capabilities.insert("project.write".into());
        }
        let writes = script.writes;
        let project = self.project.as_ref().map(|(p, _)| p.clone());
        let patches = self.patches.clone();
        let generation = self.analysis_revision;
        let ctx = self.ctx.clone();
        let (tx, rx) = mpsc::sync_channel(1);
        script.receiver = Some(rx);
        script.busy = true;
        script.revision = Some((
            self.generation,
            self.analysis_revision,
            self.project_revision,
        ));
        std::thread::spawn(move || {
            let result = (|| -> Result<_, String> {
                let mut service =
                    ura_service::Service::new(ura_service::PathPolicy::allow_all(), writes);
                let handle = if let (Some(binary), Some(analysis), Some(info)) = snapshot {
                    service
                        .extension_attach(ura_service::extensions::NativeSnapshot {
                            binary: (*binary).clone(),
                            analysis: (*analysis).clone(),
                            info,
                            project,
                            patches,
                            generation,
                        })
                        .map_err(|e| e.to_string())?
                } else {
                    String::new()
                };
                let capabilities = config.capabilities.clone();
                let host = Arc::new(ExtensionHost::new(Arc::new(Mutex::new(service)), config)?);
                let p = if handle.is_empty() {
                    json!({"session":""})
                } else {
                    host.rpc(json!({"operation":"scripts","action":"open","handle":handle,"capabilities":capabilities}))?
                };
                Ok((host, json!({"handle":handle,"session":p["session"]})))
            })();
            let reply = match result {
                Ok((host, v)) => Reply {
                    key: "initialize",
                    result: Ok(v),
                    host: Some(host),
                },
                Err(e) => Reply {
                    key: "initialize",
                    result: Err(e),
                    host: None,
                },
            };
            let _ = tx.send(reply);
            ctx.request_repaint();
        });
    }
    pub fn scripting_view(&mut self, ui: &mut egui::Ui, plugins: bool) {
        ui.label("CPython 3.14.9 · SDK 1 · trusted code with your OS permissions. The worker is not a security sandbox.");
        let running = self.scripting.host.is_some();
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    !self.scripting.busy && !running,
                    egui::Button::new("Enable trusted Python session"),
                )
                .clicked()
            {
                self.initialize_scripting();
            }
            if ui
                .add_enabled(running, egui::Button::new("Stop session"))
                .clicked()
            {
                self.scripting.reset();
            }
            ui.add_enabled_ui(!running, |ui| {
                ui.checkbox(&mut self.scripting.writes, "Permit project writes");
            });
        });
        if !running {
            ui.horizontal(|ui| {
                ui.label("Host API grants");
                ui.text_edit_singleline(&mut self.scripting.grants);
            });
            ui.horizontal(|ui| {
                ui.label("Plugin folder");
                ui.text_edit_singleline(&mut self.scripting.registry);
            });
        }
        if let Some(error) = &self.scripting.error {
            ui.colored_label(self.colors().error, error);
        }
        if plugins {
            self.plugins_view(ui);
            return;
        }
        ui.horizontal(|ui|{
            if ui.add_enabled(running && !self.scripting.session.is_empty() && !self.scripting.busy && self.scripting.job.is_empty(),egui::Button::new("Run")).clicked(){let code=self.scripting.code.clone();if self.scripting.history.last()!=Some(&code){self.scripting.history.push(code.clone());if self.scripting.history.len()>64{self.scripting.history.remove(0);}}self.scripting.history_index=self.scripting.history.len();self.scripting.rpc("run",json!({"operation":"scripts","action":"run","session":self.scripting.session,"code":code,"filename":self.scripting.file.as_ref().map(|p|p.to_string_lossy().into_owned()).unwrap_or_else(||"<ura-console>".into())}),&self.ctx);}
            if ui.add_enabled(!self.scripting.job.is_empty(),egui::Button::new("Cancel")).clicked(){self.scripting.rpc("cancel",json!({"operation":"scripts","action":"cancel","job":self.scripting.job}),&self.ctx);}
            if ui.button("Open .py").clicked()&& let Some(path)=rfd::FileDialog::new().add_filter("Python",&["py"]).pick_file(){match std::fs::metadata(&path){Ok(m) if m.len()<=65536=>match std::fs::read_to_string(&path){Ok(s)=>{self.scripting.code=s;self.scripting.file=Some(path);},Err(e)=>self.scripting.error=Some(e.to_string())},_=>self.scripting.error=Some("Script must be UTF-8 and at most64KiB".into())}}
            if ui.button("Previous").clicked() && !self.scripting.history.is_empty(){self.scripting.history_index=self.scripting.history_index.saturating_sub(1);self.scripting.code=self.scripting.history[self.scripting.history_index].clone();}
            if ui.button("Copy output").clicked(){ui.ctx().copy_text(self.scripting.output.clone());}
            if ui.button("Clear").clicked(){self.scripting.output.clear();}
        });
        if running && self.scripting.session.is_empty() {
            ui.label("Plugin host enabled. Open and analyze a binary, then restart the session to use the console.");
        }
        ui.add(
            egui::TextEdit::multiline(&mut self.scripting.code)
                .code_editor()
                .desired_rows(10)
                .desired_width(f32::INFINITY),
        );
        ui.label(if self.scripting.job.is_empty() {
            "Interpreter idle; variables persist until session restart"
        } else {
            "Python job running"
        });
        egui::ScrollArea::vertical()
            .id_salt("python-output")
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut self.scripting.output)
                        .code_editor()
                        .desired_width(f32::INFINITY)
                        .interactive(false),
                );
            });
    }
    fn plugins_view(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui|{ui.label("Plugin ZIP");ui.text_edit_singleline(&mut self.scripting.plugin_path);if ui.button("Browse").clicked()&& let Some(p)=rfd::FileDialog::new().add_filter("Plugin ZIP",&["zip"]).pick_file(){self.scripting.plugin_path=p.to_string_lossy().into_owned();}
            if ui.button("Install disabled").clicked(){self.scripting.rpc("install",json!({"operation":"plugins","action":"install","path":self.scripting.plugin_path}),&self.ctx);}
            if ui.button("Refresh").clicked(){self.scripting.rpc("inventory",json!({"operation":"plugins","action":"list"}),&self.ctx);}});
        ui.horizontal(|ui| {
            ui.label("Configuration JSON");
            ui.text_edit_singleline(&mut self.scripting.configuration);
        });
        ui.horizontal(|ui| {
            ui.label("Extension input");
            ui.text_edit_singleline(&mut self.scripting.input_path);
            if ui.button("Choose file").clicked()
                && let Some(p) = rfd::FileDialog::new().pick_file()
            {
                self.scripting.input_path = p.to_string_lossy().into_owned();
            }
        });
        let rows = self.scripting.inventory["plugins"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        for row in rows {
            let m = &row["manifest"];
            let id = m["id"]
                .as_str()
                .or_else(|| row["id"].as_str())
                .unwrap_or("")
                .to_string();
            ui.collapsing(format!("{} {} · {}",m["name"],m["version"],if row["enabled"]==true{"enabled"}else{"disabled"}),|ui|{ui.label(format!("{id} · author {} · license {}",m["author"],m["license"]));ui.label(m["description"].as_str().unwrap_or("Invalid plugin metadata"));ui.label(format!("Declared grants: {}",m["requiredCapabilities"]));ui.horizontal(|ui|{
            if ui.button("Enable with declared grants").clicked(){match serde_json::from_str::<Value>(&self.scripting.configuration){Ok(configuration)=>self.scripting.rpc("enable",json!({"operation":"plugins","action":"enable","id":id,"capabilities":m["requiredCapabilities"],"configuration":configuration}),&self.ctx),Err(e)=>self.scripting.error=Some(e.to_string())}}
            for (title,action) in [("Disable","disable"),("Uninstall","uninstall")]{if ui.button(title).clicked(){self.scripting.rpc(action,json!({"operation":"plugins","action":action,"id":id}),&self.ctx);}}
            if m["analyzer"].is_string() && ui.button("Run analyzer").clicked(){self.scripting.rpc("run",json!({"operation":"plugins","action":"run","id":id,"kind":"analyzer","handle":self.scripting.handle}),&self.ctx);}
        });for kind in ["loader","processor"]{if m[kind].is_string() && ui.button(format!("Run {kind} on input")).clicked(){self.scripting.rpc("run",json!({"operation":"plugins","action":"run","id":id,"kind":kind,"path":self.scripting.input_path}),&self.ctx);}}
        if let Some(commands)=m["commands"].as_array(){ui.menu_button("Commands",|ui|{for command in commands{if ui.button(command["title"].as_str().unwrap_or("Command")).clicked(){self.scripting.rpc("run",json!({"operation":"plugins","action":"run","id":id,"command":command["id"],"handle":self.scripting.handle,"parameters":{"address":self.location.address.map(ura_core::format_address)}}),&self.ctx);ui.close();}}});}});
        }
        ui.separator();
        ui.label("Advanced plugin/loader/processor/batch request (same versioned SDK controller)");
        ui.add(
            egui::TextEdit::multiline(&mut self.scripting.batch_request)
                .code_editor()
                .desired_rows(3)
                .desired_width(f32::INFINITY),
        );
        if ui.button("Submit explicit request").clicked() {
            match serde_json::from_str::<Value>(&self.scripting.batch_request) {
                Ok(p) => self.scripting.rpc("request", p, &self.ctx),
                Err(e) => self.scripting.error = Some(e.to_string()),
            }
        }
        let result = self.scripting.result.clone();
        if result["state"] == "complete"
            && result["sourcePlugin"].is_string()
            && (result["value"]["segments"].is_array()
                || result["value"]["instructions"].is_array())
            && ui.button("Validate and open extension result").clicked()
        {
            self.scripting.rpc(
                "accept",
                json!({"operation":"plugins","action":"accept","job":result["id"]}),
                &self.ctx,
            );
        }
        if !self.scripting.context_handle.is_empty() {
            ui.horizontal(|ui|{ui.label(format!("{} {} address",self.scripting.context_kind,self.scripting.context_handle));ui.text_edit_singleline(&mut self.scripting.navigation);if ui.button("Navigate").clicked(){let operation=self.scripting.context_kind.clone();let action=if operation=="image"{"disassembly"}else{"page"};self.scripting.rpc("navigate",json!({"operation":operation,"action":action,"handle":self.scripting.context_handle,"address":self.scripting.navigation}),&self.ctx);}});
        }
        if let Some(instructions) = result["instructions"].as_array() {
            for i in instructions {
                ui.horizontal(|ui|{ui.monospace(format!("{} {} {}",i["address"],i["mnemonic"],i["operands"]));if let Some(target)=i["target"].as_str()&& ui.link(target).clicked(){self.scripting.navigation=target.into();let operation=self.scripting.context_kind.clone();let action=if operation=="image"{"disassembly"}else{"page"};self.scripting.rpc("navigate",json!({"operation":operation,"action":action,"handle":self.scripting.context_handle,"address":target}),&self.ctx);}});
            }
        }

        if result["identityStatus"] != "stale"
            && let Some(findings) = result["findings"].as_array()
        {
            for f in findings {
                if ui
                    .link(format!(
                        "{} · {} · {}",
                        f["sourcePlugin"], f["address"], f["title"]
                    ))
                    .clicked()
                    && let Some(a) = f["address"]
                        .as_str()
                        .and_then(|a| ura_core::parse_address(a).ok())
                {
                    self.navigate_address(a);
                }
                ui.label(f["explanation"].as_str().unwrap_or(""));
            }
        }
        egui::ScrollArea::vertical()
            .id_salt("plugin-results")
            .show(ui, |ui| {
                let text=serde_json::to_string_pretty(&result).unwrap_or_default();if text.len()>65536{ui.label("Preview limited to64KiB; full bounded result remains available through the SDK controller.");}ui.monospace(text.chars().take(65536).collect::<String>());
            });
    }
}
