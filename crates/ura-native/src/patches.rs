use crate::{
    app::{Action, Workspace},
    worker::{Control, Event, TaskKind},
};
use eframe::egui;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
use ura_core::patch::{Address, Preview};

pub struct PatchEditor {
    instruction: bool,
    offset: String,
    budget: usize,
    input: String,
    comment: String,
    padding: bool,
    preview: Option<Preview>,
    listing: Vec<String>,
    error: Option<String>,
}
pub enum Change {
    Apply(Preview),
    History(&'static str, Option<u64>),
}
impl Workspace {
    pub fn open_patch_editor(&mut self, instruction: bool) {
        if self.opening || self.project.is_none() {
            self.log(true, "Save a project before editing bytes.");
            return;
        }
        let Some(doc) = &self.patches else {
            self.log(true, "Patching is unavailable for this format or mapping.");
            return;
        };
        let selected = self.location.file_offset.or_else(|| {
            self.location
                .address
                .and_then(|a| doc.offset(Address::VirtualAddress(a), 1).ok())
        });
        let Some(offset) = selected else {
            self.log(true, "Select a file-backed byte or instruction.");
            return;
        };
        let budget = if instruction {
            let Some(i) = self
                .location
                .address
                .and_then(|a| self.analysis.as_ref()?.instructions.get(&a))
            else {
                self.log(true, "Select a currently decoded instruction start.");
                return;
            };
            i.length as usize
        } else {
            1
        };
        let input = if instruction {
            String::new()
        } else {
            doc.read(Address::FileOffset(offset), budget)
                .unwrap_or_default()
                .iter()
                .map(|b| format!("{b:02X} "))
                .collect()
        };
        self.patch_editor = Some(PatchEditor {
            instruction,
            offset: format!("{offset:X}"),
            budget,
            input,
            comment: String::new(),
            padding: false,
            preview: None,
            listing: vec![],
            error: None,
        });
    }
    pub fn patch_dialog(&mut self, ctx: &egui::Context) {
        let Some(mut editor) = self.patch_editor.take() else {
            return;
        };
        let mut open = true;
        let mut close = false;
        egui::Window::new(if editor.instruction {"Patch instruction"} else {"Edit bytes"}).open(&mut open).default_width(620.0).resizable(true).show(ctx,|ui| {
            ui.label("Changes are stored in the project. The original file stays unchanged.");
            let mut changed=false;
            ui.horizontal(|ui| {ui.label("File offset (hex)");changed|=ui.text_edit_singleline(&mut editor.offset).changed();ui.label("Byte budget");changed|=ui.add(egui::DragValue::new(&mut editor.budget).range(1..=if editor.instruction {256} else {65536})).changed();});
            ui.label(if editor.instruction {"Intel assembly (register/immediate operations and direct branches; no memory operands)"} else {"Replacement hexadecimal byte pairs (length must equal budget)"});
            changed|=ui.add(egui::TextEdit::multiline(&mut editor.input).font(egui::TextStyle::Monospace).desired_rows(3)).changed();
            if editor.instruction {changed|=ui.checkbox(&mut editor.padding,"Pad shorter replacement with NOPs").changed();}
            ui.horizontal(|ui| {ui.label("Comment");changed|=ui.text_edit_singleline(&mut editor.comment).changed();});
            if changed {editor.preview=None;editor.listing.clear();editor.error=None;}
            if ui.button("Preview").clicked() {
                let result=(||->Result<Preview,String> {
                    let doc=self.patches.as_ref().ok_or("No patchable binary")?;
                    let offset=ura_core::parse_address(&editor.offset).map_err(|e|e.to_string())?;
                    if editor.instruction {
                        let origin=doc.virtual_address(offset,editor.budget).ok_or("No unambiguous virtual origin")?;
                        if !self.analysis.as_ref().is_some_and(|a|a.instructions.contains_key(&origin)) {return Err("Analyse current bytes and select an instruction start.".into());}
                        let preview=doc.preview_instruction(Address::FileOffset(offset),editor.budget,&editor.input,editor.padding,&editor.comment).map_err(|e|e.to_string())?;
                        editor.listing=preview.original_instructions.into_iter().map(|s|format!("Before: {s}")).chain(preview.replacement_instructions.into_iter().map(|s|format!("After:  {s}"))).collect();
                        Ok(preview.patch)
                    } else {
                        let replacement=ura_core::patch::parse_hex(&editor.input).map_err(|e|e.to_string())?;
                        if replacement.len()!=editor.budget {return Err("Replacement length must equal the explicit byte budget.".into());}
                        let expected=doc.read(Address::FileOffset(offset),editor.budget).map_err(|e|e.to_string())?;
                        doc.preview(Address::FileOffset(offset),&expected,&replacement,&editor.comment).map_err(|e|e.to_string())
                    }
                })();
                match result {Ok(p)=>{editor.preview=Some(p);editor.error=None;},Err(e)=>{editor.preview=None;editor.error=Some(e);}}
            }
            if let Some(error)=&editor.error {ui.colored_label(self.colors().error,error);}
            if let Some(p)=&editor.preview {
                egui::ScrollArea::both().max_height(240.0).show(ui,|ui| {
                    for edit in &p.edits {ui.monospace(format!("0x{:X}  {:02X?} → {:02X?}",edit.offset,edit.before,edit.after));}
                    for line in &editor.listing {ui.monospace(line);}
                });
                if ui.add_enabled(!self.opening,egui::Button::new("Apply to project")).clicked() {self.actions.push(Action::PatchApply(p.clone()));close=true;}
            }
            if ui.button("Cancel").clicked() {close=true;}
        });
        if open && !close {
            self.patch_editor = Some(editor);
        }
    }
    pub fn commit_patch(&mut self, change: Change) {
        if self.opening {
            return;
        }
        let Some((project, _)) = &self.project else {
            self.log(true, "Save a project before editing bytes.");
            return;
        };
        let project = project.clone();
        let Some(mut doc) = self.patches.clone() else {
            return;
        };
        let revision = doc.state().revision;
        let path = self.binary.as_ref().unwrap().path().to_path_buf();
        self.cancel.store(true, Ordering::Relaxed);
        self.cancel = Arc::new(AtomicBool::new(false));
        let cancel = self.cancel.clone();
        self.generation += 1;
        self.opening = true;
        self.analyzing = false;
        self.scanning = false;
        self.page = None;
        self.page_loading = false;
        self.analysis = None;
        self.graph.clear();
        self.graph_loading = None;
        self.ir_key = None;
        self.ir_loading = None;
        self.ir_bundle = None;
        self.ir_rows.clear();
        self.decomp_key = None;
        self.decomp_loading = None;
        self.decomp = None;
        self.call_graph = None;
        self.call_graph_loading = false;
        self.call_graph_key = None;
        self.strings = None;
        self.log(
            false,
            "Applying patch transaction; analysis is invalidated…",
        );
        self.worker.submit_typed(self.generation,TaskKind::Patch,move || {
            match change {Change::Apply(p)=>doc.apply(&p).map(|_|()),Change::History(a,id)=>match a {"undo"=>doc.undo(),"redo"=>doc.redo(),"revert"=>doc.revert(id.ok_or("Missing patch ID")?).map(|_|()),"revertAll"=>doc.revert_all().map(|_|()),_=>return Err("Unknown patch history action".into())}}.map_err(|e|e.to_string())?;
            if cancel.load(Ordering::Relaxed) {return Err("Patch transaction cancelled before commit; reopen the project to restore its prior analysis.".into());}
            doc.effective_binary(&path).map_err(|e|e.to_string())?;
            if cancel.load(Ordering::Relaxed) {return Err("Patch transaction cancelled before commit; reopen the project.".into());}
            ura_project::save_patch_state(&project,doc.state(),revision).map_err(|e|e.to_string())?;
            crate::worker::open(project)
        });
    }
    pub fn export_patches(&mut self, manifest: bool) {
        if self.opening {
            return;
        }
        let Some(doc) = self.patches.clone() else {
            return;
        };
        let Some(binary) = &self.binary else {
            return;
        };
        let source = binary.path().to_path_buf();
        let default = if manifest {
            "patches.json".to_string()
        } else {
            format!("patched-{}", binary.file_name())
        };
        self.opening = true;
        self.cancel = Arc::new(AtomicBool::new(false));
        let control = Control {
            cancel: self.cancel.clone(),
            progress: self.progress.clone(),
            ctx: self.ctx.clone(),
            last: Mutex::new(Instant::now()),
        };
        self.worker
            .submit_typed(self.generation, TaskKind::Open, move || {
                let Some(destination) = rfd::FileDialog::new().set_file_name(default).save_file()
                else {
                    return Ok(Event::PatchExported("Export cancelled".into()));
                };
                let result = if manifest {
                    doc.export_manifest(&destination, &control)
                } else {
                    doc.export(&source, &destination, &control)
                }
                .map_err(|e| e.to_string())?;
                Ok(Event::PatchExported(format!(
                    "Exported {} bytes to {} · SHA-256 {}. {}",
                    result.bytes,
                    destination.display(),
                    result.sha256,
                    result.signature_warning
                )))
            });
    }
    pub fn patch_manager(&mut self, ui: &mut egui::Ui) {
        let available = self.patches.is_some() && !self.opening;
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    self.project.is_some() && available,
                    egui::Button::new("Edit bytes…"),
                )
                .clicked()
            {
                self.actions.push(Action::PatchDialog(false));
            }
            for (label, action) in [
                ("Undo", "undo"),
                ("Redo", "redo"),
                ("Revert all", "revertAll"),
            ] {
                if ui
                    .add_enabled(
                        available
                            && self.project.is_some()
                            && self.patches.as_ref().is_some_and(|p| match action {
                                "undo" => p.state().cursor > 0,
                                "redo" => p.state().cursor < p.state().transactions.len(),
                                _ => p.changed_bytes() > 0,
                            }),
                        egui::Button::new(label),
                    )
                    .clicked()
                {
                    self.actions.push(Action::PatchHistory(action, None));
                }
            }
            if ui
                .add_enabled(available, egui::Button::new("Export binary…"))
                .clicked()
            {
                self.actions.push(Action::PatchExport(false));
            }
            if ui
                .add_enabled(available, egui::Button::new("Export manifest…"))
                .clicked()
            {
                self.actions.push(Action::PatchExport(true));
            }
        });
        let Some(doc) = &self.patches else {
            ui.label("Patching supports linked PE/ELF files with valid file mappings. Save a project to apply changes.");
            return;
        };
        ui.label(format!(
            "{} changed bytes · revision {} · original SHA-256 {}",
            doc.changed_bytes(),
            doc.state().revision,
            doc.state().original_sha256
        ));
        ui.label("Annotations retain original address anchors; review them after instruction changes. Export may invalidate signatures.");
        egui::ScrollArea::both().show_rows(
            ui,
            self.settings.row_height,
            doc.state().transactions.len(),
            |ui, range| {
                for index in range {
                    let t = &doc.state().transactions[index];
                    let applied = index < doc.state().cursor;
                    let overlap = self.patch_conflicts.contains(&t.id);
                    ui.horizontal(|ui| {
                        ui.label(format!(
                            "#{} {} {}",
                            t.id,
                            if applied { "Applied" } else { "Undone" },
                            t.kind
                        ));
                        if let Some(e) = t.edits.first() {
                            let va = doc
                                .virtual_address(e.offset, e.after.len())
                                .map(|a| format!("0x{a:X}"))
                                .unwrap_or_else(|| "unmapped VA".into());
                            if ui
                                .small_button(format!("{} / file 0x{:X}", va, e.offset))
                                .clicked()
                            {
                                self.actions.push(Action::Navigate(
                                    crate::navigation::Location {
                                        address: doc.virtual_address(e.offset, 1),
                                        file_offset: Some(e.offset),
                                    },
                                    true,
                                ));
                            }
                            ui.monospace(format!(
                                "{:02X?} → {:02X?}",
                                &e.before[..e.before.len().min(12)],
                                &e.after[..e.after.len().min(12)]
                            ));
                        }
                        ui.label(&t.comment);
                        if overlap {
                            ui.label("Later overlap").on_hover_text(
                                "Undo overlapping later patches before reverting this transaction.",
                            );
                        }
                        if applied
                            && ui
                                .add_enabled(!self.opening && !overlap, egui::Button::new("Revert"))
                                .clicked()
                        {
                            self.actions
                                .push(Action::PatchHistory("revert", Some(t.id)));
                        }
                    });
                }
            },
        );
    }
}
