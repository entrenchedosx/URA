use crate::app::Workspace;
use eframe::egui::{self, RichText};
use std::path::PathBuf;
use ura_core::decomp::{
    CallingConvention, FunctionDecompilation, Location, SignatureOverride, SignatureParameterInput,
    StackSlot, StructField, Structure, TypeDatabase, TypeRef,
};

pub struct ParameterEdit {
    name: String,
    location: String,
    ty: String,
    original: Option<SignatureParameterInput>,
}
pub enum EditValue {
    Signature {
        convention: CallingConvention,
        return_type: String,
        original_return: Option<TypeRef>,
        parameters: Vec<ParameterEdit>,
        variadic: Option<bool>,
    },
    Stack {
        offset: i64,
        name: String,
        ty: String,
        original_type: Option<TypeRef>,
    },
    Structure {
        original: Option<String>,
        name: String,
        size: String,
        alignment: String,
        union: bool,
        fields: Vec<FieldEdit>,
    },
    Alias {
        original: Option<String>,
        name: String,
        ty: String,
        original_type: Option<TypeRef>,
    },
}
pub struct FieldEdit {
    name: String,
    offset: String,
    ty: String,
    original: Option<StructField>,
}
pub struct Editor {
    project: PathBuf,
    function: u64,
    bits: u16,
    value: EditValue,
    error: Option<String>,
}

fn location_text(location: &Location) -> String {
    match location {
        Location::Register { name } => name.clone(),
        Location::Stack { offset, .. } => format!("stack:{offset}"),
        Location::Unknown { .. } => "unknown".into(),
    }
}
fn parse_location(text: &str, bits: u16) -> Result<Location, String> {
    let text = text.trim().to_ascii_lowercase();
    if text == "unknown" {
        return Ok(Location::Unknown {
            reason: "location not supplied by user".into(),
        });
    }
    if let Some(offset) = text.strip_prefix("stack:") {
        let offset = offset
            .parse::<i64>()
            .map_err(|_| "Use stack: followed by a signed byte offset")?;
        if offset.unsigned_abs() > 1 << 30 {
            return Err("Stack offset is outside the supported range".into());
        }
        return Ok(Location::Stack {
            offset,
            width: bits,
        });
    }
    // The shared signature validator checks this name against the selected ABI.
    if text.starts_with(|c: char| c.is_ascii_alphabetic())
        && text.chars().all(|c| c.is_ascii_alphanumeric())
    {
        return Ok(Location::Register { name: text });
    }
    Err("Use a general register, stack:offset, or unknown".into())
}

impl Workspace {
    pub fn edit_structure(&mut self, structure: Option<&Structure>) {
        let Some((path, _)) = &self.project else {
            return;
        };
        self.editor = Some(Editor {
            project: path.clone(),
            function: 0,
            bits: self
                .binary
                .as_ref()
                .map_or(64, |b| b.analysis().bitness as u16),
            error: None,
            value: EditValue::Structure {
                original: structure.map(|s| s.name.clone()),
                name: structure.map_or_else(|| "NewStruct".into(), |s| s.name.clone()),
                size: structure
                    .and_then(|s| s.size)
                    .map_or_else(String::new, |v| v.to_string()),
                alignment: structure
                    .and_then(|s| s.alignment)
                    .map_or_else(String::new, |v| v.to_string()),
                union: structure.is_some_and(|s| s.union),
                fields: structure.map_or_else(Vec::new, |s| {
                    s.fields
                        .iter()
                        .map(|f| FieldEdit {
                            name: f.name.clone(),
                            offset: f.offset.to_string(),
                            ty: f.ty.display(),
                            original: Some(f.clone()),
                        })
                        .collect()
                }),
            },
        });
    }
    pub fn edit_alias(&mut self, name: Option<&str>, ty: Option<&TypeRef>) {
        let Some((path, _)) = &self.project else {
            return;
        };
        self.editor = Some(Editor {
            project: path.clone(),
            function: 0,
            bits: self
                .binary
                .as_ref()
                .map_or(64, |b| b.analysis().bitness as u16),
            error: None,
            value: EditValue::Alias {
                original: name.map(str::to_string),
                name: name.unwrap_or("NewType").into(),
                ty: ty.map_or_else(|| "u32".into(), TypeRef::display),
                original_type: ty.cloned(),
            },
        });
    }
    pub fn edit_signature(&mut self, data: &FunctionDecompilation) {
        let Some((path, _)) = &self.project else {
            return;
        };
        self.editor = Some(Editor {
            project: path.clone(),
            function: data.function,
            bits: data.frame.address_width,
            value: EditValue::Signature {
                convention: data.signature.convention,
                return_type: data.signature.return_value.ty.display(),
                original_return: Some(data.signature.return_value.ty.clone()),
                parameters: data
                    .signature
                    .parameters
                    .iter()
                    .map(|p| ParameterEdit {
                        name: p.name.clone(),
                        location: location_text(&p.location),
                        ty: p.ty.display(),
                        original: Some(SignatureParameterInput {
                            name: p.name.clone(),
                            location: p.location.clone(),
                            ty: p.ty.clone(),
                        }),
                    })
                    .collect(),
                variadic: data.signature.variadic,
            },
            error: None,
        });
    }
    pub fn edit_stack_slot(&mut self, function: u64, slot: &StackSlot) {
        let Some((path, _)) = &self.project else {
            return;
        };
        self.editor = Some(Editor {
            project: path.clone(),
            function,
            bits: self
                .binary
                .as_ref()
                .map_or(64, |b| b.analysis().bitness as u16),
            value: EditValue::Stack {
                offset: slot.offset,
                name: slot.user_name.clone().unwrap_or_else(|| slot.name.clone()),
                ty: slot.user_type.as_ref().unwrap_or(&slot.ty).display(),
                original_type: Some(slot.user_type.as_ref().unwrap_or(&slot.ty).clone()),
            },
            error: None,
        });
    }
    pub fn decompiler_editor(&mut self, ctx: &egui::Context) {
        let Some(mut editor) = self.editor.take() else {
            return;
        };
        if self.project.as_ref().map(|p| &p.0) != Some(&editor.project) {
            return;
        }
        let mut open = true;
        let mut save = false;
        let mut reset = false;
        let processor = self.binary.as_ref().and_then(|binary| {
            ura_core::processor::Processor::for_analysis(binary.analysis()).ok()
        });
        egui::Window::new(match editor.value {
            EditValue::Signature { .. } => "Edit function signature",
            EditValue::Stack { .. } => "Edit stack variable",
            EditValue::Structure { .. } => "Edit structure",
            EditValue::Alias { .. } => "Edit type alias",
        })
        .open(&mut open)
        .collapsible(false)
        .default_width(620.0)
        .show(ctx, |ui| {
            if editor.function != 0 {
                ui.label(RichText::new(ura_core::format_address(editor.function)).monospace());
            }
            match &mut editor.value {
                EditValue::Signature {
                    convention,
                    return_type,
                    parameters,
                    variadic,
                    ..
                } => {
                    ui.horizontal(|ui| {
                        ui.label("Calling convention");
                        egui::ComboBox::from_id_salt("edit-convention")
                            .selected_text(convention.name())
                            .show_ui(ui, |ui| {
                                for cc in [
                                    CallingConvention::Aapcs64,
                                    CallingConvention::Aapcs32,
                                    CallingConvention::Riscv32,
                                    CallingConvention::Riscv64,
                                    CallingConvention::Win64,
                                    CallingConvention::SysV64,
                                    CallingConvention::Cdecl,
                                    CallingConvention::Stdcall,
                                    CallingConvention::Fastcall,
                                    CallingConvention::Thiscall,
                                    CallingConvention::Unknown,
                                ] {
                                    let probe = SignatureOverride {
                                        convention: cc,
                                        return_type: TypeRef::Void,
                                        parameters: Vec::new(),
                                        variadic: None,
                                    };
                                    if !processor.map_or_else(
                                        || probe.validate_for_width(editor.bits),
                                        |p| probe.validate_for_processor(p),
                                    ).is_empty() {
                                        continue;
                                    }
                                    ui.selectable_value(convention, cc, cc.name());
                                }
                            });
                        ui.label("Return type");
                        ui.text_edit_singleline(return_type);
                    });
                    ui.small(
                        "Locations: an ABI register (rcx, x0, r0, a0), stack:40 (entry-relative byte offset), or unknown.",
                    );
                    let mut remove = None;
                    egui::ScrollArea::vertical()
                        .max_height(320.0)
                        .show(ui, |ui| {
                            egui::Grid::new("edit-signature-parameters")
                                .num_columns(4)
                                .striped(true)
                                .show(ui, |ui| {
                                    for label in ["Name", "Location", "Type", ""] {
                                        ui.strong(label);
                                    }
                                    ui.end_row();
                                    for (index, parameter) in parameters.iter_mut().enumerate() {
                                        ui.add(
                                            egui::TextEdit::singleline(&mut parameter.name)
                                                .min_size(egui::vec2(130.0, 0.0)),
                                        );
                                        ui.add(
                                            egui::TextEdit::singleline(&mut parameter.location)
                                                .min_size(egui::vec2(110.0, 0.0)),
                                        );
                                        ui.add(
                                            egui::TextEdit::singleline(&mut parameter.ty)
                                                .min_size(egui::vec2(150.0, 0.0)),
                                        );
                                        if ui.small_button("Remove").clicked() {
                                            remove = Some(index);
                                        }
                                        ui.end_row();
                                    }
                                });
                        });
                    if let Some(index) = remove {
                        parameters.remove(index);
                    }
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(parameters.len() < 64, egui::Button::new("Add parameter"))
                            .clicked()
                        {
                            parameters.push(ParameterEdit {
                                name: format!("a{}", parameters.len()),
                                location: "unknown".into(),
                                ty: format!("int{}", editor.bits),
                                original: None,
                            });
                        }
                        ui.label("Variadic");
                        egui::ComboBox::from_id_salt("edit-variadic")
                            .selected_text(match variadic {
                                None => "Unknown",
                                Some(false) => "No",
                                Some(true) => "Yes",
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(variadic, None, "Unknown");
                                ui.selectable_value(variadic, Some(false), "No");
                                ui.selectable_value(variadic, Some(true), "Yes");
                            });
                    });
                }
                EditValue::Stack {
                    offset, name, ty, ..
                } => {
                    ui.label(format!("Physical stack offset {offset:+} bytes"));
                    egui::Grid::new("edit-stack-variable")
                        .num_columns(2)
                        .show(ui, |ui| {
                            ui.label("Name");
                            ui.add(
                                egui::TextEdit::singleline(name).min_size(egui::vec2(400.0, 0.0)),
                            );
                            ui.end_row();
                            ui.label("Type");
                            ui.add(egui::TextEdit::singleline(ty).min_size(egui::vec2(400.0, 0.0)));
                            ui.end_row();
                        });
                    ui.small("Leave a field empty to retain only the other override.");
                }
                EditValue::Alias { name, ty, .. } => {
                    ui.horizontal(|ui| {
                        ui.label("Name");
                        ui.text_edit_singleline(name);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Target type");
                        ui.text_edit_singleline(ty);
                    });
                }
                EditValue::Structure {
                    name,
                    size,
                    alignment,
                    union,
                    fields,
                    ..
                } => {
                    ui.horizontal(|ui| {
                        ui.label("Name");
                        ui.text_edit_singleline(name);
                        ui.checkbox(union, "Union");
                    });
                    ui.horizontal(|ui| {
                        ui.label("Size (bytes)");
                        ui.add(egui::TextEdit::singleline(size).desired_width(90.0));
                        ui.label("Alignment");
                        ui.add(egui::TextEdit::singleline(alignment).desired_width(90.0));
                    });
                    ui.small(
                        "Leave size or alignment empty when unknown. Offsets are decimal bytes.",
                    );
                    let mut remove = None;
                    egui::ScrollArea::vertical()
                        .max_height(320.0)
                        .show(ui, |ui| {
                            egui::Grid::new("edit-structure-fields")
                                .num_columns(4)
                                .striped(true)
                                .show(ui, |ui| {
                                    for label in ["Field", "Offset", "Type", ""] {
                                        ui.strong(label);
                                    }
                                    ui.end_row();
                                    for (index, field) in fields.iter_mut().enumerate() {
                                        ui.add(
                                            egui::TextEdit::singleline(&mut field.name)
                                                .min_size(egui::vec2(140.0, 0.0)),
                                        );
                                        ui.add(
                                            egui::TextEdit::singleline(&mut field.offset)
                                                .min_size(egui::vec2(70.0, 0.0)),
                                        );
                                        ui.add(
                                            egui::TextEdit::singleline(&mut field.ty)
                                                .min_size(egui::vec2(170.0, 0.0)),
                                        );
                                        if ui.small_button("Remove").clicked() {
                                            remove = Some(index);
                                        }
                                        ui.end_row();
                                    }
                                });
                        });
                    if let Some(index) = remove {
                        fields.remove(index);
                    }
                    if ui
                        .add_enabled(fields.len() < 512, egui::Button::new("Add field"))
                        .clicked()
                    {
                        fields.push(FieldEdit {
                            name: format!("field{}", fields.len()),
                            offset: "0".into(),
                            ty: "u32".into(),
                            original: None,
                        });
                    }
                }
            }
            if let Some(error) = &editor.error {
                ui.colored_label(self.colors().error, error);
            }
            ui.separator();
            ui.horizontal(|ui| {
                save = ui.button("Save to project").clicked();
                reset = ui
                    .button(
                        if matches!(
                            editor.value,
                            EditValue::Structure { .. } | EditValue::Alias { .. }
                        ) {
                            "Delete definition"
                        } else {
                            "Use inferred values"
                        },
                    )
                    .clicked();
            });
        });
        let address = ura_core::format_address(editor.function);
        if reset {
            if matches!(
                editor.value,
                EditValue::Structure { .. } | EditValue::Alias { .. }
            ) {
                let mut library = self
                    .project
                    .as_ref()
                    .and_then(|p| p.1.type_library.clone())
                    .unwrap_or_else(|| TypeDatabase::new(editor.bits));
                match &editor.value {
                    EditValue::Structure {
                        original: Some(name),
                        ..
                    } => {
                        library.structures.remove(name);
                    }
                    EditValue::Alias {
                        original: Some(name),
                        ..
                    } => {
                        library.typedefs.remove(name);
                    }
                    _ => return,
                }
                self.edit_project(move |path| {
                    ura_project::save_type_library(path, &library).map_err(|e| e.to_string())
                });
                return;
            }
            self.edit_project(move |path| match editor.value {
                EditValue::Signature { .. } => {
                    ura_project::delete_function_signature(path, &address)
                        .map(|_| ())
                        .map_err(|e| e.to_string())
                }
                EditValue::Stack { offset, .. } => {
                    ura_project::delete_stack_variable(path, &address, offset)
                        .map(|_| ())
                        .map_err(|e| e.to_string())
                }
                _ => unreachable!(),
            });
            return;
        }
        if save {
            let library = self
                .project
                .as_ref()
                .and_then(|p| p.1.type_library.clone())
                .unwrap_or_else(|| TypeDatabase::new(editor.bits));
            match editor.parsed(&library) {
                Ok(EditCommit::Signature(value)) => {
                    self.edit_project(move |path| {
                        ura_project::save_function_signature(path, &address, &value)
                            .map(|_| ())
                            .map_err(|e| e.to_string())
                    });
                    return;
                }
                Ok(EditCommit::Stack(offset, name, ty)) => {
                    self.edit_project(move |path| {
                        ura_project::save_stack_variable(
                            path,
                            &address,
                            offset,
                            name.as_deref(),
                            ty.as_ref(),
                        )
                        .map(|_| ())
                        .map_err(|e| e.to_string())
                    });
                    return;
                }
                Ok(EditCommit::Library(library)) => {
                    self.edit_project(move |path| {
                        ura_project::save_type_library(path, &library).map_err(|e| e.to_string())
                    });
                    return;
                }
                Err(error) => editor.error = Some(error),
            }
        }
        if open {
            self.editor = Some(editor);
        }
    }
}
enum EditCommit {
    Signature(SignatureOverride),
    Stack(i64, Option<String>, Option<TypeRef>),
    Library(TypeDatabase),
}
impl Editor {
    fn parsed(&self, library: &TypeDatabase) -> Result<EditCommit, String> {
        match &self.value {
            EditValue::Signature {
                convention,
                return_type,
                original_return,
                parameters,
                variadic,
            } => {
                let value = SignatureOverride {
                    convention: *convention,
                    return_type: parse_preserving_type(
                        return_type,
                        self.bits,
                        original_return.as_ref(),
                    )?,
                    parameters: parameters
                        .iter()
                        .map(|p| {
                            Ok(SignatureParameterInput {
                                name: p.name.trim().into(),
                                location: match p.original.as_ref() {
                                    Some(original)
                                        if location_text(&original.location)
                                            == p.location.trim().to_ascii_lowercase() =>
                                    {
                                        original.location.clone()
                                    }
                                    _ => parse_location(&p.location, self.bits)?,
                                },
                                ty: parse_preserving_type(
                                    &p.ty,
                                    self.bits,
                                    p.original.as_ref().map(|p| &p.ty),
                                )?,
                            })
                        })
                        .collect::<Result<_, String>>()?,
                    variadic: *variadic,
                };
                let errors = value.validate_for_width(self.bits);
                if !errors.is_empty() {
                    return Err(errors.join("; "));
                }
                Ok(EditCommit::Signature(value))
            }
            EditValue::Stack {
                offset,
                name,
                ty,
                original_type,
            } => {
                let name = if name.trim().is_empty() {
                    None
                } else {
                    Some(name.trim().to_string())
                };
                let ty = if ty.trim().is_empty() {
                    None
                } else {
                    Some(parse_preserving_type(
                        ty,
                        self.bits,
                        original_type.as_ref(),
                    )?)
                };
                if name.is_none() && ty.is_none() {
                    return Err("Supply a name or type, or choose Use inferred values".into());
                }
                Ok(EditCommit::Stack(*offset, name, ty))
            }
            EditValue::Alias {
                original,
                name,
                ty,
                original_type,
            } => {
                let mut library = library.clone();
                if original.as_ref().is_some_and(|old| old != name) {
                    return Err("Create a new alias to use a different name; existing references retain their names".into());
                }
                if original.is_none() && library.typedefs.contains_key(name.trim()) {
                    return Err("A type alias with this name already exists".into());
                }
                library.typedefs.insert(
                    name.trim().into(),
                    parse_preserving_type(ty, self.bits, original_type.as_ref())?,
                );
                let errors = library.validation_errors();
                if !errors.is_empty() {
                    return Err(errors.join("; "));
                }
                Ok(EditCommit::Library(library))
            }
            EditValue::Structure {
                original,
                name,
                size,
                alignment,
                union,
                fields,
            } => {
                let mut library = library.clone();
                if original.as_ref().is_some_and(|old| old != name) {
                    return Err("Create a new definition to use a different name; existing references retain their names".into());
                }
                if original.is_none() && library.structures.contains_key(name.trim()) {
                    return Err("A structure with this name already exists".into());
                }
                let number = |text: &str| -> Result<Option<u64>, String> {
                    if text.trim().is_empty() {
                        Ok(None)
                    } else {
                        text.trim().parse().map(Some).map_err(|_| {
                            "Size and alignment must be nonnegative decimal integers".into()
                        })
                    }
                };
                let structure = Structure {
                    name: name.trim().into(),
                    size: number(size)?,
                    alignment: number(alignment)?,
                    union: *union,
                    source: "user".into(),
                    fields: fields
                        .iter()
                        .map(|field| {
                            Ok(StructField {
                                name: field.name.trim().into(),
                                offset: field.offset.trim().parse().map_err(
                                    |_| "Field offset must be a nonnegative decimal integer",
                                )?,
                                ty: parse_preserving_type(
                                    &field.ty,
                                    self.bits,
                                    field.original.as_ref().map(|f| &f.ty),
                                )?,
                                size: field
                                    .original
                                    .as_ref()
                                    .filter(|f| f.ty.display() == field.ty.trim())
                                    .and_then(|f| f.size),
                                source: field
                                    .original
                                    .as_ref()
                                    .filter(|f| f.ty.display() == field.ty.trim())
                                    .map_or_else(|| "user".into(), |f| f.source.clone()),
                            })
                        })
                        .collect::<Result<_, String>>()?,
                };
                library.structures.insert(structure.name.clone(), structure);
                let errors = library.validation_errors();
                if !errors.is_empty() {
                    return Err(errors.join("; "));
                }
                Ok(EditCommit::Library(library))
            }
        }
    }
}

fn parse_preserving_type(
    text: &str,
    bits: u16,
    original: Option<&TypeRef>,
) -> Result<TypeRef, String> {
    if let Some(original) = original.filter(|original| original.display() == text.trim()) {
        Ok(original.clone())
    } else {
        TypeRef::parse(text, bits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signature_editor_preserves_unknown_types_and_rejects_invalid_locations() {
        let mut editor = Editor {
            project: PathBuf::new(),
            function: 1,
            bits: 64,
            error: None,
            value: EditValue::Signature {
                convention: CallingConvention::Win64,
                return_type: "unknown64".into(),
                original_return: None,
                variadic: Some(false),
                parameters: vec![ParameterEdit {
                    name: "count".into(),
                    location: "rcx".into(),
                    ty: "int32".into(),
                    original: None,
                }],
            },
        };
        let EditCommit::Signature(signature) = editor.parsed(&TypeDatabase::new(64)).unwrap()
        else {
            panic!()
        };
        assert!(matches!(
            signature.return_type,
            TypeRef::Unknown { bits: Some(64), .. }
        ));
        assert_eq!(signature.parameters[0].ty, TypeRef::int(32));
        if let EditValue::Signature { parameters, .. } = &mut editor.value {
            parameters[0].location = "some register".into();
        }
        assert!(editor.parsed(&TypeDatabase::new(64)).is_err());
        for (cc, bits, register, invalid) in [
            (CallingConvention::Aapcs64, 64, "x7", "rax"),
            (CallingConvention::Aapcs32, 32, "r3", "x0"),
            (CallingConvention::Riscv32, 32, "a7", "zero"),
            (CallingConvention::Riscv64, 64, "s11", "x0"),
        ] {
            editor.bits = bits;
            if let EditValue::Signature {
                convention,
                parameters,
                ..
            } = &mut editor.value
            {
                *convention = cc;
                parameters[0].location = register.into();
            }
            let EditCommit::Signature(saved) = editor.parsed(&TypeDatabase::new(bits)).unwrap()
            else {
                panic!()
            };
            assert!(
                matches!(&saved.parameters[0].location, Location::Register { name } if name == register)
            );
            if let EditValue::Signature { parameters, .. } = &mut editor.value {
                parameters[0].location = invalid.into();
            }
            assert!(editor.parsed(&TypeDatabase::new(bits)).is_err());
        }
    }
    #[test]
    fn structure_editor_checks_real_field_sizes_before_saving() {
        let mut editor = Editor {
            project: PathBuf::new(),
            function: 0,
            bits: 64,
            error: None,
            value: EditValue::Structure {
                original: None,
                name: "Header".into(),
                size: "4".into(),
                alignment: "4".into(),
                union: false,
                fields: vec![FieldEdit {
                    name: "length".into(),
                    offset: "0".into(),
                    ty: "u64".into(),
                    original: None,
                }],
            },
        };
        assert!(editor.parsed(&TypeDatabase::new(64)).is_err());
        if let EditValue::Structure { fields, .. } = &mut editor.value {
            fields[0].ty = "u32".into();
        }
        let EditCommit::Library(library) = editor.parsed(&TypeDatabase::new(64)).unwrap() else {
            panic!()
        };
        assert_eq!(library.structures["Header"].fields[0].ty, TypeRef::uint(32));
    }

    #[test]
    fn signature_editor_preserves_structured_types_stack_width_and_unknown_variadic() {
        let return_type = TypeRef::unknown(Some(64), "return register was not defined");
        let parameter = SignatureParameterInput {
            name: "value".into(),
            location: Location::Stack {
                offset: 40,
                width: 32,
            },
            ty: TypeRef::pointer_to(TypeRef::uint(8), 32),
        };
        let editor = Editor {
            project: PathBuf::new(),
            function: 1,
            bits: 64,
            error: None,
            value: EditValue::Signature {
                convention: CallingConvention::Win64,
                return_type: return_type.display(),
                original_return: Some(return_type.clone()),
                parameters: vec![ParameterEdit {
                    name: "renamed".into(),
                    location: location_text(&parameter.location),
                    ty: parameter.ty.display(),
                    original: Some(parameter.clone()),
                }],
                variadic: None,
            },
        };
        let EditCommit::Signature(signature) = editor.parsed(&TypeDatabase::new(64)).unwrap()
        else {
            panic!()
        };
        assert_eq!(signature.return_type, return_type);
        assert_eq!(signature.parameters[0].ty, parameter.ty);
        assert_eq!(signature.parameters[0].location, parameter.location);
        assert_eq!(signature.parameters[0].name, "renamed");
        assert_eq!(signature.variadic, None);
    }

    #[test]
    fn structure_alignment_edit_preserves_field_types_storage_and_provenance() {
        let structure = Structure {
            name: "Record".into(),
            size: Some(16),
            alignment: Some(4),
            union: false,
            source: "header".into(),
            fields: vec![
                StructField {
                    name: "tag".into(),
                    offset: 0,
                    ty: TypeRef::Enum {
                        name: "Tag".into(),
                        underlying: Box::new(TypeRef::uint(8)),
                    },
                    size: Some(4),
                    source: "tag header".into(),
                },
                StructField {
                    name: "address".into(),
                    offset: 4,
                    ty: TypeRef::pointer_to(TypeRef::uint(8), 32),
                    size: Some(4),
                    source: "address header".into(),
                },
                StructField {
                    name: "callback".into(),
                    offset: 8,
                    ty: TypeRef::pointer_to(
                        TypeRef::Function {
                            return_type: Box::new(TypeRef::Void),
                            parameters: vec![TypeRef::uint(32)],
                            variadic: false,
                        },
                        64,
                    ),
                    size: Some(8),
                    source: "callback header".into(),
                },
            ],
        };
        let mut library = TypeDatabase::new(64);
        library
            .structures
            .insert(structure.name.clone(), structure.clone());
        let editor = Editor {
            project: PathBuf::new(),
            function: 0,
            bits: 64,
            error: None,
            value: EditValue::Structure {
                original: Some(structure.name.clone()),
                name: structure.name.clone(),
                size: "16".into(),
                alignment: "8".into(),
                union: false,
                fields: structure
                    .fields
                    .iter()
                    .map(|field| FieldEdit {
                        name: field.name.clone(),
                        offset: field.offset.to_string(),
                        ty: field.ty.display(),
                        original: Some(field.clone()),
                    })
                    .collect(),
            },
        };
        let EditCommit::Library(saved) = editor.parsed(&library).unwrap() else {
            panic!()
        };
        assert_eq!(saved.structures["Record"].alignment, Some(8));
        for (before, after) in structure
            .fields
            .iter()
            .zip(&saved.structures["Record"].fields)
        {
            assert_eq!(before.ty, after.ty);
            assert_eq!(before.size, after.size);
            assert_eq!(before.source, after.source);
        }
    }

    #[test]
    fn stack_and_alias_editors_preserve_types_without_parseable_display_spellings() {
        let ty = TypeRef::pointer_to(
            TypeRef::Function {
                return_type: Box::new(TypeRef::uint(32)),
                parameters: vec![],
                variadic: true,
            },
            32,
        );
        assert!(TypeRef::parse(&ty.display(), 64).is_err());
        let stack_editor = Editor {
            project: PathBuf::new(),
            function: 1,
            bits: 64,
            error: None,
            value: EditValue::Stack {
                offset: -8,
                name: "callback".into(),
                ty: ty.display(),
                original_type: Some(ty.clone()),
            },
        };
        let EditCommit::Stack(_, _, saved) = stack_editor.parsed(&TypeDatabase::new(64)).unwrap()
        else {
            panic!()
        };
        assert_eq!(saved, Some(ty.clone()));
        let mut library = TypeDatabase::new(64);
        library.typedefs.insert("Callback".into(), ty.clone());
        let alias_editor = Editor {
            project: PathBuf::new(),
            function: 0,
            bits: 64,
            error: None,
            value: EditValue::Alias {
                original: Some("Callback".into()),
                name: "Callback".into(),
                ty: ty.display(),
                original_type: Some(ty.clone()),
            },
        };
        let EditCommit::Library(saved) = alias_editor.parsed(&library).unwrap() else {
            panic!()
        };
        assert_eq!(saved.typedefs["Callback"], ty);
        assert_eq!(
            parse_preserving_type("u32", 64, Some(&ty)).unwrap(),
            TypeRef::uint(32)
        );
    }
}
