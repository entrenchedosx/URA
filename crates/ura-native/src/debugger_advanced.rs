use super::*;
impl DebugUi {
    pub(super) fn advanced_breakpoint_controls(&mut self, ui: &mut egui::Ui) {
        ui.collapsing("Breakpoint type and condition",|ui|{
            let kinds=["Software","Hardware execution","Write watchpoint","Read/write watchpoint"];
            egui::ComboBox::from_id_salt("point-kind").selected_text(kinds[self.breakpoint_kind.min(3)]).show_ui(ui,|ui|{for (i,label) in kinds.iter().enumerate(){ui.selectable_value(&mut self.breakpoint_kind,i,*label);}});
            if ![1,2,4,8].contains(&self.breakpoint_length){self.breakpoint_length=1;}
            ui.horizontal(|ui|{ui.label("Watched bytes");for len in [1,2,4,8]{ui.selectable_value(&mut self.breakpoint_length,len,len.to_string());}});
            ui.horizontal(|ui|{ui.label("Thread ID (empty: all)");ui.text_edit_singleline(&mut self.breakpoint_thread);});
            ui.horizontal(|ui|{ui.label("Register condition");ui.text_edit_singleline(&mut self.breakpoint_condition);});
            self.hit_after=self.hit_after.max(1);self.hit_every=self.hit_every.max(1);
            ui.horizontal(|ui|{ui.label("First eligible hit");ui.add(egui::DragValue::new(&mut self.hit_after).range(1..=u64::MAX));ui.label("Every");ui.add(egui::DragValue::new(&mut self.hit_every).range(1..=u64::MAX));});
            if ui.add_enabled(!self.busy && self.snapshot.state==State::Paused,egui::Button::new("Set configured breakpoint at address below")).clicked(){
                let thread=if self.breakpoint_thread.trim().is_empty(){None}else{match self.breakpoint_thread.trim().parse::<u32>(){Ok(t)=>Some(t),Err(_)=>{self.error=Some("Thread ID must be a decimal number.".into());return;}}};
                let kind=["software","hardwareExecute","write","readWrite"][self.breakpoint_kind.min(3)];
                self.request("breakpoint",json!({"operation":"configureBreakpoint","address":self.breakpoint_address,"kind":kind,"length":if self.breakpoint_kind==0{1}else{self.breakpoint_length},"thread":thread,"condition":if self.breakpoint_condition.trim().is_empty(){None}else{Some(&self.breakpoint_condition)},"hitAfter":self.hit_after,"hitEvery":self.hit_every}),ui.ctx());
            }
            ui.label("Unsigned register expressions; no scripts or live memory evaluation.");
        });
    }
    pub(super) fn snapshot_controls(&mut self, ui: &mut egui::Ui) {
        ui.collapsing("Captured memory and regions",|ui|{
            let paused=self.snapshot.state==State::Paused && !self.busy;
            if self.capture_length==0{self.capture_length=4096;}
            ui.horizontal(|ui|{
                ui.label("Capture bytes at runtime address below");ui.add(egui::DragValue::new(&mut self.capture_length).range(1..=1048576));
                if ui.add_enabled(paused,egui::Button::new("Capture")).clicked(){self.request("capture",json!({"operation":"snapshot","action":"capture","address":self.memory_address,"length":self.capture_length}),ui.ctx());}
                if ui.add_enabled(paused,egui::Button::new("Regions")).clicked(){self.request("regions",json!({"operation":"memoryRegions","address":self.memory_address,"limit":64}),ui.ctx());}
            });
            ui.horizontal(|ui|{
                ui.label("Snapshot ID");ui.add(egui::DragValue::new(&mut self.capture_id).range(1..=u64::MAX));
                for (label,kind,action) in [("List","captures","list"),("View","capture","info"),("Compare live","compare","compare"),("Remove","captures","remove")]{
                    if ui.add_enabled(!self.busy && (action!="compare" || paused),egui::Button::new(label)).clicked(){let mut req=json!({"operation":"snapshot","action":action});if action!="list"{req["id"]=json!(self.capture_id);}self.request(kind,req,ui.ctx());}
                }
                if ui.add_enabled(!self.busy,egui::Button::new("Decode captured bytes")).clicked(){self.request("snapshotDisasm",json!({"operation":"snapshot","action":"disassembly","id":self.capture_id,"address":self.memory_address,"count":16}),ui.ctx());}
            });
            ui.horizontal(|ui|{
                ui.label("Compare with snapshot ID");ui.text_edit_singleline(&mut self.capture_other);
                if ui.add_enabled(!self.busy,egui::Button::new("Compare captures")).clicked(){match self.capture_other.parse::<u64>(){Ok(other)=>self.request("compare",json!({"operation":"snapshot","action":"compare","id":self.capture_id,"other":other}),ui.ctx()),Err(_)=>self.error=Some("Enter a decimal comparison snapshot ID.".into())}}
            });
            ui.horizontal(|ui|{ui.label("New export file");ui.text_edit_singleline(&mut self.export_path);if ui.add_enabled(!self.busy && !self.export_path.is_empty(),egui::Button::new("Export selected capture")).clicked(){self.request("export",json!({"operation":"snapshot","action":"export","id":self.capture_id,"destination":self.export_path}),ui.ctx());}});
            if let Some(value)=self.advanced.get("capture"){
                ui.label(format!("Captured {} / {} bytes at {} · missing {} · SHA-256 {}",value["captured"],value["requested"],value["address"],value["missing"],value["capturedBytesSha256"]));
                if let Some(chunks)=value["chunks"].as_array(){
                    egui::ScrollArea::both().max_height(180.0).id_salt("snapshot-bytes").show(ui,|ui|{
                        let mut remaining=256;
                        for chunk in chunks{
                            let base=chunk["address"].as_str().and_then(|a|ura_core::parse_address(a).ok()).unwrap_or(0);
                            if let Some(bytes)=chunk["bytes"].as_array(){
                                for (i,row) in bytes.iter().take(remaining).collect::<Vec<_>>().chunks(16).enumerate(){
                                    let data=row.iter().map(|b|b.as_u64().unwrap_or(0) as u8).collect::<Vec<_>>();
                                    ui.monospace(format!("{:016X}  {}  {}",base+i as u64*16,data.iter().map(|b|format!("{b:02X}")).collect::<Vec<_>>().join(" "),data.iter().map(|&b|if b.is_ascii_graphic(){b as char}else{'.'}).collect::<String>()));
                                }
                                remaining=remaining.saturating_sub(bytes.len());
                            }
                            if chunk["missing"].as_u64().unwrap_or(0)>0{ui.label(format!("Missing range at {}: {}",chunk["address"],chunk["error"]));}
                            if remaining==0{break;}
                        }
                    });
                }
            }
            for key in ["captures","compare","export"]{if let Some(value)=self.advanced.get(key){ui.label(format!("{key}: {value}"));}}
            if let Some(rows)=self.advanced["regions"]["regions"].as_array(){egui::ScrollArea::vertical().max_height(120.0).id_salt("memory-regions").show_rows(ui,18.0,rows.len(),|ui,range|{for row in &rows[range]{ui.monospace(format!("{} +{} protection={} readable={}",row["base"],row["size"],row["protection"],row["readable"]));}});}
            if let Some(rows)=self.advanced["snapshotDisasm"]["instructions"].as_array(){for row in rows{ui.monospace(format!("{}  {}",row["address"],row["text"]));}}
            ui.label("Captured runtime bytes are immutable evidence, with gaps retained. Exports create a new local JSON file; no executable reconstruction or automatic project storage.");
        });
    }
    pub(super) fn symbol_controls(&mut self, ui: &mut egui::Ui) {
        ui.collapsing("Local symbols",|ui|{
            ui.horizontal(|ui|{ui.label("Explicit PDB file");ui.text_edit_singleline(&mut self.pdb_path);if ui.add_enabled(!self.busy && self.snapshot.state==State::Paused,egui::Button::new("Load matching main-image PDB")).clicked()
                && let Some(base)=self.snapshot.modules.iter().find(|m|m.sha256.is_some()).map(|m|m.base.clone()){self.request("symbols",json!({"operation":"symbols","action":"load","base":base,"pdb":self.pdb_path}),ui.ctx());}});
            ui.horizontal(|ui|{ui.label("Runtime symbol address");ui.text_edit_singleline(&mut self.symbol_address);if ui.add_enabled(!self.busy && self.snapshot.state==State::Paused,egui::Button::new("Look up")).clicked(){self.request("symbols",json!({"operation":"symbols","action":"lookup","address":self.symbol_address}),ui.ctx());}});
            if let Some(value)=self.advanced.get("symbols"){ui.label(value.to_string());}
            ui.label("Local MSF7 PDB with matching RSDS GUID/age. No network lookup or C++ type recovery.");
        });
    }
}
impl Workspace {
    pub(super) fn trace_panel(&mut self, ui: &mut egui::Ui) {
        let debug = &mut self.debugger;
        ui.horizontal_wrapped(|ui|{
            ui.checkbox(&mut debug.trace_instructions,"Instruction stepping");
            if debug.trace_steps==0{debug.trace_steps=1000;}
            ui.label("Step limit");ui.add(egui::DragValue::new(&mut debug.trace_steps).range(1..=100000));
            for (label,action) in [("Start","start"),("Stop","stop"),("Clear","clear"),("Read page","read")]{
                let enabled=!debug.busy && (action!="start" || debug.snapshot.state==State::Paused);
                if ui.add_enabled(enabled,egui::Button::new(label)).clicked(){
                    let request=match action{
                        "start"=>json!({"operation":"trace","action":"start","config":{"mode":if debug.trace_instructions{"instructions"}else{"events"},"maxSteps":debug.trace_steps,"maxEvents":4096,"maxBytes":1048576,"maxDurationMs":5000,"registers":true}}),
                        "read"=>json!({"operation":"trace","action":"read","after":debug.trace_after,"limit":512}),
                        _=>json!({"operation":"trace","action":action}),
                    };debug.request("trace",request,ui.ctx());
                }
            }
        });
        ui.label(format!("Current collection: {}", debug.snapshot.trace));
        ui.horizontal(|ui| {
            ui.label("Thread");
            ui.text_edit_singleline(&mut debug.trace_thread);
            ui.label("Module");
            ui.text_edit_singleline(&mut debug.trace_module);
            ui.label("Address");
            ui.text_edit_singleline(&mut debug.trace_address);
        });
        ui.horizontal(|ui| {
            ui.label("After sequence");
            ui.add(egui::DragValue::new(&mut debug.trace_after));
            ui.label("New export file");
            ui.text_edit_singleline(&mut debug.export_path);
            if ui
                .add_enabled(
                    !debug.busy && !debug.export_path.is_empty(),
                    egui::Button::new("Export trace"),
                )
                .clicked()
            {
                debug.request(
                    "export",
                    json!({"operation":"trace","action":"export","destination":debug.export_path}),
                    ui.ctx(),
                );
            }
        });
        let events = debug.advanced["trace"]["events"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let filtered = events
            .iter()
            .filter(|e| {
                (debug.trace_thread.is_empty()
                    || debug
                        .trace_thread
                        .parse::<u64>()
                        .ok()
                        .is_some_and(|t| e["thread"].as_u64() == Some(t)))
                    && (debug.trace_module.is_empty()
                        || e["module"]["path"]
                            .as_str()
                            .unwrap_or("")
                            .to_ascii_lowercase()
                            .contains(&debug.trace_module.to_ascii_lowercase()))
                    && (debug.trace_address.is_empty()
                        || e["address"]
                            .as_str()
                            .unwrap_or("")
                            .to_ascii_lowercase()
                            .contains(&debug.trace_address.to_ascii_lowercase()))
            })
            .collect::<Vec<_>>();
        let mut selected = None;
        egui::ScrollArea::both()
            .id_salt("observed-trace")
            .show_rows(ui, 18.0, filtered.len(), |ui, range| {
                for event in &filtered[range] {
                    if ui
                        .selectable_label(
                            false,
                            RichText::new(format!(
                                "{}  T{}  {}  {}  {}",
                                event["sequence"],
                                event["thread"],
                                event["address"].as_str().unwrap_or(""),
                                event["kind"].as_str().unwrap_or(""),
                                event["module"]["path"].as_str().unwrap_or("")
                            ))
                            .monospace(),
                        )
                        .on_hover_text(event["detail"].to_string())
                        .clicked()
                    {
                        selected = Some((*event).clone());
                    }
                }
            });
        if let Some(last) = events.last().and_then(|e| e["sequence"].as_u64())
            && ui.button("Next page").clicked()
        {
            debug.trace_after = last;
            debug.request(
                "trace",
                json!({"operation":"trace","action":"read","after":last,"limit":512}),
                ui.ctx(),
            );
        }
        if let Some(event) = selected {
            debug.advanced["selectedTrace"] = event;
        }
        let selected = debug.advanced["selectedTrace"].clone();
        if selected.is_object() {
            ui.label(format!("Captured detail: {}", selected["detail"]));
            if ui.button("Navigate observed instruction").clicked() {
                if let Some(address) = self.trace_static_address(&selected) {
                    self.navigate_address(address);
                    self.actions.push(Action::Show(Panel::Disassembly));
                } else {
                    self.debugger.error =
                        Some("This observation has no matching static image mapping.".into());
                }
            }
        }
        let mut frequencies = std::collections::BTreeMap::<String, usize>::new();
        for e in &events {
            if e["kind"] == "instruction"
                && let Some(address) = e["address"].as_str()
            {
                *frequencies.entry(address.into()).or_default() += 1;
            }
        }
        ui.collapsing("Instruction frequencies in this page", |ui| {
            for (address, count) in frequencies.iter().take(256) {
                ui.monospace(format!("{address}: {count} observed captures"));
            }
        });
        ui.label("Observed evidence after trace start, subject to retention limits. A visited path does not exclude other static paths. Single-step tracing can be expensive.");
    }
    fn trace_static_address(&self, event: &Value) -> Option<u64> {
        let info = self.info.as_ref()?;
        if self
            .patches
            .as_ref()
            .is_some_and(|p| p.changed_bytes() != 0)
            || event["module"]["sha256"].as_str() != Some(&info.sha256)
        {
            return None;
        }
        let rva = ura_core::parse_address(event["module"]["rva"].as_str()?).ok()?;
        if rva >= event["module"]["size"].as_u64()? {
            return None;
        }
        ura_core::parse_address(&info.image_base)
            .ok()?
            .checked_add(rva)
    }
}
