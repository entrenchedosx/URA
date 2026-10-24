use crate::{error::ServiceResult, service::Session, Service, ServiceError};
use serde::Serialize;
use std::path::Path;
use ura_core::patch::{
    Address, Exported, InstructionPreview, PatchDocument, PatchError, PatchState, Preview,
};

fn patch_error(e: PatchError) -> ServiceError {
    ServiceError::InvalidArgument(e.to_string())
}
pub fn patch_address(space: &str, value: &str) -> ServiceResult<Address> {
    let value = ura_core::parse_address(value)?;
    match space {
        "offset" => Ok(Address::FileOffset(value)),
        "va" => Ok(Address::VirtualAddress(value)),
        "rva" => Ok(Address::Rva(value)),
        _ => Err(ServiceError::InvalidArgument(
            "address space must be offset, va or rva; values are hexadecimal".into(),
        )),
    }
}
fn document(session: &Session) -> ServiceResult<&PatchDocument> {
    session.patches.as_ref().ok_or_else(|| {
        ServiceError::InvalidArgument(
            "patching requires supported linked PE/ELF file mappings".into(),
        )
    })
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PatchList {
    pub schema_version: u32,
    pub state: PatchState,
    pub changed_bytes: usize,
    pub format: String,
    pub bitness: u32,
    pub analysis_current: bool,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveBytes {
    pub schema_version: u32,
    pub offset: String,
    pub original: Vec<u8>,
    pub current: Vec<u8>,
    pub revision: u64,
}

impl Service {
    pub fn list_patches(&self, handle: &str) -> ServiceResult<PatchList> {
        let s = self.session(handle)?;
        let p = document(s)?;
        Ok(PatchList {
            schema_version: 1,
            state: p.state().clone(),
            changed_bytes: p.changed_bytes(),
            format: p.format().into(),
            bitness: p.bitness(),
            analysis_current: s.analysis.is_some(),
        })
    }
    pub fn read_effective_bytes(
        &self,
        handle: &str,
        address: Address,
        length: usize,
    ) -> ServiceResult<EffectiveBytes> {
        let p = document(self.session(handle)?)?;
        let offset = p.offset(address, length).map_err(patch_error)?;
        Ok(EffectiveBytes {
            schema_version: 1,
            offset: format!("0x{offset:X}"),
            original: p.original()[offset as usize..offset as usize + length].to_vec(),
            current: p.read(address, length).map_err(patch_error)?,
            revision: p.state().revision,
        })
    }
    pub fn preview_byte_patch(
        &self,
        handle: &str,
        address: Address,
        expected: &[u8],
        replacement: &[u8],
        comment: &str,
    ) -> ServiceResult<Preview> {
        document(self.session(handle)?)?
            .preview(address, expected, replacement, comment)
            .map_err(patch_error)
    }
    pub fn preview_instruction_patch(
        &mut self,
        handle: &str,
        address: Address,
        budget: usize,
        text: &str,
        pad: bool,
        comment: &str,
    ) -> ServiceResult<InstructionPreview> {
        let session = self
            .sessions
            .get(handle)
            .ok_or_else(|| ServiceError::UnknownHandle(handle.into()))?;
        let doc = document(session)?;
        let offset = doc.offset(address, budget).map_err(patch_error)?;
        let origin = doc.virtual_address(offset, budget).ok_or_else(|| {
            ServiceError::InvalidArgument(
                "instruction region needs a unique virtual address".into(),
            )
        })?;
        // Require a currently decoded instruction start. The user explicitly
        // supplies the overwrite budget; core validates every covered boundary.
        let mut found = false;
        if let Some(analysis) = &session.analysis {
            found = analysis.instructions.contains_key(&origin);
        }
        if !found {
            return Err(ServiceError::InvalidArgument("analyse current bytes and select a decoded instruction start before assembly editing".into()));
        }
        doc.preview_instruction(address, budget, text, pad, comment)
            .map_err(patch_error)
    }
    fn mutate_patches(
        &mut self,
        handle: &str,
        project: &Path,
        change: impl FnOnce(&mut PatchDocument) -> Result<(), PatchError>,
    ) -> ServiceResult<PatchList> {
        self.require_writes()?;
        let resolved = self.policy.allow_write(project)?;
        let session = self.session(handle)?;
        let attached = session.project.as_ref().ok_or_else(|| {
            ServiceError::InvalidArgument("save/open a project before applying patches".into())
        })?;
        if self.policy.allow_read(attached)? != resolved {
            return Err(ServiceError::InvalidArgument(
                "patch writes must target the attached project".into(),
            ));
        }
        let snapshot = ura_project::read_project(&resolved)?;
        let doc = document(session)?;
        if snapshot.project.binary_hash != doc.state().original_sha256 {
            return Err(ServiceError::ProjectBinaryMismatch);
        }
        let revision = doc.state().revision;
        let mut candidate = doc.clone();
        change(&mut candidate).map_err(patch_error)?;
        // One full immutable analysis snapshot per accepted transaction; old
        // analysis and all derived caches are discarded together.
        let binary = candidate.effective_binary(session.binary.path())?;
        let open = binary.open_result();
        ura_project::save_patch_state(&resolved, candidate.state(), revision)?;
        let session = self.sessions.get_mut(handle).unwrap();
        session.binary = binary;
        session.patches = Some(candidate);
        session.sections = open.sections;
        session.imports = open.imports;
        session.exports = open.exports;
        session.analysis = None;
        session.analysis_generation = session.analysis_generation.wrapping_add(1);
        session.analysis_options = None;
        session.ir_cache.clear();
        session.ir_cache_order.clear();
        session.decomp_cache.clear();
        session.decomp_cache_order.clear();
        self.list_patches(handle)
    }
    pub fn apply_patch(
        &mut self,
        handle: &str,
        project: &Path,
        preview: &Preview,
    ) -> ServiceResult<PatchList> {
        self.mutate_patches(handle, project, |d| d.apply(preview).map(|_| ()))
    }
    pub fn patch_history(
        &mut self,
        handle: &str,
        project: &Path,
        action: &str,
        id: Option<u64>,
    ) -> ServiceResult<PatchList> {
        self.mutate_patches(handle, project, |d| match action {
            "undo" => d.undo(),
            "redo" => d.redo(),
            "revert" => d
                .revert(id.ok_or_else(|| PatchError("revert needs a patch ID".into()))?)
                .map(|_| ()),
            "revertAll" => d.revert_all().map(|_| ()),
            _ => Err(PatchError(
                "history action must be undo, redo, revert or revertAll".into(),
            )),
        })
    }
    pub fn export_patched_binary(
        &self,
        handle: &str,
        destination: &Path,
    ) -> ServiceResult<Exported> {
        self.require_writes()?;
        let destination = self.policy.allow_write(destination)?;
        let s = self.session(handle)?;
        let source = self.policy.allow_read(s.binary.path())?;
        document(s)?
            .export(&source, &destination, &())
            .map_err(patch_error)
    }
    pub fn export_patch_manifest(
        &self,
        handle: &str,
        destination: &Path,
    ) -> ServiceResult<Exported> {
        self.require_writes()?;
        let destination = self.policy.allow_write(destination)?;
        document(self.session(handle)?)?
            .export_manifest(&destination, &())
            .map_err(patch_error)
    }
}
