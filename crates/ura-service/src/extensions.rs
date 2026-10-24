//! Shared extension API helpers; the worker host checks capabilities separately.
use crate::{error::ServiceResult, Service, ServiceError};
use serde_json::{json, Value};
use ura_core::{format_address, parse_address};

pub struct NativeSnapshot {
    pub binary: ura_core::LoadedBinary,
    pub analysis: ura_core::ProgramAnalysis,
    pub info: ura_core::BinaryView,
    pub project: Option<std::path::PathBuf>,
    pub patches: Option<ura_core::patch::PatchDocument>,
    pub generation: u64,
}

impl Service {
    /// Attach the exact effective native snapshot, including its patch overlay.
    /// Called off the paint thread; script operations still use normal Service APIs.
    pub fn extension_attach(&mut self, input: NativeSnapshot) -> ServiceResult<String> {
        if self.sessions.len() >= 8 {
            return Err(ServiceError::LimitExceeded(
                "At most8 binary handles".into(),
            ));
        }
        let snapshot = input
            .project
            .as_deref()
            .map(ura_project::read_project)
            .transpose()?;
        if snapshot
            .as_ref()
            .is_some_and(|s| s.project.binary_hash != input.info.sha256)
        {
            return Err(ServiceError::ProjectBinaryMismatch);
        }
        let opened = input.binary.open_result();
        let bits = input.binary.analysis().bitness as u16;
        let mut session = crate::service::Session {
            binary: input.binary,
            analysis: Some(input.analysis),
            info: input.info,
            project: input.project,
            patches: input.patches,
            analysis_generation: input.generation,
            sections: opened.sections,
            imports: opened.imports,
            exports: opened.exports,
            names: Default::default(),
            manual: Default::default(),
            signature_overrides: Default::default(),
            stack_overrides: Default::default(),
            type_library: ura_core::decomp::types::TypeDatabase::new(bits),
            analysis_options: Some(Default::default()),
            ir_cache: Default::default(),
            ir_cache_order: Default::default(),
            decomp_cache: Default::default(),
            decomp_cache_order: Default::default(),
        };
        if let Some(s) = snapshot {
            session.names = crate::service::names_from_snapshot(&s);
            session.manual = crate::service::manual_from_snapshot(&s);
            session.signature_overrides = crate::service::signature_overrides_from_snapshot(&s);
            session.stack_overrides = crate::service::stack_overrides_from_snapshot(&s);
            if let Some(library) = s.type_library {
                session.type_library = library;
            }
        }
        let handle = format!("bin{}", self.next_handle);
        self.next_handle += 1;
        self.sessions.insert(handle.clone(), session);
        Ok(handle)
    }
    pub fn extension_identity(&self, handle: &str) -> ServiceResult<String> {
        let s = self.session(handle)?;
        let revision = s
            .project
            .as_deref()
            .map(ura_project::scripting::metadata_revision)
            .transpose()?;
        Ok(ura_core::sha256_hex(
            &serde_json::to_vec(&(
                s.binary.content_sha256(),
                s.analysis_generation,
                &s.project,
                &s.names,
                &s.signature_overrides,
                &s.stack_overrides,
                &s.type_library,
                revision,
            ))
            .map_err(|e| ServiceError::Serialization(e.to_string()))?,
        ))
    }
    pub fn extension_metadata(&self, handle: &str) -> ServiceResult<Value> {
        let s = self.session(handle)?;
        Ok(
            json!({"handle":handle,"identity":self.extension_identity(handle)?,"generation":s.analysis_generation,
            "project":s.project,"binary":s.info,"effectiveSha256":s.binary.content_sha256(),
            "sections":s.sections,"imports":s.imports.iter().take(256).collect::<Vec<_>>(),"exports":s.exports.iter().take(256).collect::<Vec<_>>(),"symbolCount":s.binary.analysis().symbols.len(),"metadataPartial":s.imports.len()>256 || s.exports.len()>256}),
        )
    }
    pub fn extension_symbols(
        &self,
        handle: &str,
        offset: usize,
        limit: usize,
    ) -> ServiceResult<Value> {
        if !(1..=256).contains(&limit) {
            return Err(ServiceError::LimitExceeded(
                "symbol page limit1..256".into(),
            ));
        }
        let s = self.session(handle)?;
        let symbols = s.binary.analysis().symbol_view_list();
        Ok(
            json!({"total":symbols.len(),"offset":offset,"symbols":symbols.into_iter().skip(offset).take(limit).collect::<Vec<_>>(),"provenance":"original file symbols; user overrides are separate function metadata"}),
        )
    }
    pub fn extension_policy(&self) -> crate::PathPolicy {
        self.policy.clone()
    }
    pub fn extension_writes_enabled(&self) -> bool {
        self.writes_enabled
    }
    pub fn extension_bytes(
        &self,
        handle: &str,
        address: &str,
        length: usize,
        original: bool,
    ) -> ServiceResult<Value> {
        if !(1..=8192).contains(&length) {
            return Err(ServiceError::LimitExceeded("byte read limit1..8192".into()));
        }
        let s = self.session(handle)?;
        let address = parse_address(address)?;
        let offset = s
            .binary
            .analysis()
            .sections
            .iter()
            .find_map(|r| {
                let delta = address.checked_sub(r.address)?;
                if address.checked_add(length as u64).is_none()
                    || delta.checked_add(length as u64)? > r.file_size.min(r.size)
                {
                    return None;
                }
                r.file_offset_for_address(address)
            })
            .ok_or_else(|| {
                ServiceError::InvalidArgument("address has no file-backed bytes".into())
            })?;
        let end = offset
            .checked_add(length as u64)
            .ok_or_else(|| ServiceError::InvalidArgument("byte range overflow".into()))?;
        let bytes = if original {
            s.patches
                .as_ref()
                .map(|p| p.original())
                .unwrap_or_else(|| s.binary.bytes())
        } else {
            s.binary.bytes()
        };
        let selected = bytes
            .get(
                offset as usize
                    ..usize::try_from(end)
                        .map_err(|e| ServiceError::InvalidArgument(e.to_string()))?,
            )
            .ok_or_else(|| ServiceError::InvalidArgument("byte range outside file".into()))?;
        Ok(
            json!({"address":format_address(address),"space":if original{"original-file"}else{"effective-file"},"bytes":selected}),
        )
    }
    pub fn extension_mapping(&self, handle: &str, address: &str) -> ServiceResult<Value> {
        let s = self.session(handle)?;
        let a = parse_address(address)?;
        let section = s
            .binary
            .analysis()
            .sections
            .iter()
            .find(|v| v.contains_address(a));
        Ok(
            json!({"address":format_address(a),"valid":section.is_some(),"fileOffset":section.and_then(|v|v.file_offset_for_address(a)).map(format_address),"rva":a.checked_sub(s.binary.analysis().image_base).map(format_address),"section":section.map(|v|v.view()),"space":"effective-file-image"}),
        )
    }
    pub fn extension_transaction(
        &mut self,
        handle: &str,
        expected: &str,
        edits: &[ura_project::scripting::MetadataEdit],
    ) -> ServiceResult<Value> {
        self.require_writes()?;
        let project = self.session(handle)?.project.clone().ok_or_else(|| {
            ServiceError::InvalidArgument("a saved project is required for metadata writes".into())
        })?;
        let revision = ura_project::scripting::metadata_revision(&project)?;
        if self.extension_identity(handle)? != expected {
            return Err(ServiceError::InvalidArgument(
                "stale script/project identity".into(),
            ));
        }
        let s = self.session(handle)?;
        let project = s.project.clone().ok_or_else(|| {
            ServiceError::InvalidArgument("a saved project is required for metadata writes".into())
        })?;
        let project = self.policy.allow_write(&project)?;
        for edit in edits {
            if let ura_project::scripting::MetadataEdit::TypeLibrary { library } = edit {
                if library.address_bits != s.binary.analysis().bitness as u16 {
                    return Err(ServiceError::InvalidArgument(
                        "Type library address width mismatch".into(),
                    ));
                }
                continue;
            }
            let address = match edit {
                ura_project::scripting::MetadataEdit::Rename { address, .. }
                | ura_project::scripting::MetadataEdit::Comment { address, .. }
                | ura_project::scripting::MetadataEdit::Signature { address, .. }
                | ura_project::scripting::MetadataEdit::StackVariable { address, .. } => address,
                _ => unreachable!(),
            };
            let a = parse_address(address)?;
            if !s
                .binary
                .analysis()
                .sections
                .iter()
                .any(|r| r.contains_address(a))
            {
                return Err(ServiceError::InvalidArgument(
                    "annotation outside mapped image".into(),
                ));
            }
            if !matches!(edit, ura_project::scripting::MetadataEdit::Comment { .. })
                && !s
                    .analysis
                    .as_ref()
                    .is_some_and(|p| p.function_by_start(a).is_some())
            {
                return Err(ServiceError::FunctionNotFound(address.clone()));
            }
            if let ura_project::scripting::MetadataEdit::Signature { signature, .. } = edit {
                let processor = ura_core::processor::Processor::for_analysis(s.binary.analysis())
                    .map_err(ServiceError::InvalidArgument)?;
                let errors = signature.validate_for_processor(processor);
                if !errors.is_empty() {
                    return Err(ServiceError::InvalidArgument(errors.join("; ")));
                }
            }
        }
        ura_project::scripting::apply(&project, &s.info.sha256, &revision, edits)?;
        let s = self.sessions.get_mut(handle).unwrap();
        for edit in edits {
            match edit {
                ura_project::scripting::MetadataEdit::Rename { address, name } => {
                    s.names.insert(parse_address(address)?, name.trim().into());
                }
                ura_project::scripting::MetadataEdit::Signature { address, signature } => {
                    s.signature_overrides
                        .insert(parse_address(address)?, signature.clone());
                }
                ura_project::scripting::MetadataEdit::StackVariable {
                    address,
                    offset,
                    name,
                    ty,
                } => {
                    let variables = s
                        .stack_overrides
                        .entry(parse_address(address)?)
                        .or_default();
                    if name.is_none() && ty.is_none() {
                        variables.remove(&offset.to_string());
                    } else {
                        variables.insert(
                            offset.to_string(),
                            (name.as_ref().map(|n| n.trim().into()), ty.clone()),
                        );
                    }
                }
                ura_project::scripting::MetadataEdit::TypeLibrary { library } => {
                    s.type_library = library.clone()
                }
                _ => {}
            }
        }
        s.decomp_cache.clear();
        s.decomp_cache_order.clear();
        self.symbolic.invalidate_handle(handle);
        let generation = self.sessions[handle].analysis_generation;
        for edit in edits {
            let kind = match edit {
                ura_project::scripting::MetadataEdit::Rename { .. } => "function.renamed",
                ura_project::scripting::MetadataEdit::Comment { .. } => "comment.changed",
                _ => "metadata.changed",
            };
            self.events.emit(
                kind,
                handle,
                generation,
                self.event_origin.as_deref(),
                json!(edit),
            );
        }
        Ok(
            json!({"committed":edits.len(),"identity":self.extension_identity(handle)?,"transaction":"atomic project metadata; no binary patch/undo history modification"}),
        )
    }
    pub fn extension_origin(&mut self, origin: Option<String>) {
        self.event_origin = origin;
    }
}
