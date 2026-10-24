//! Fixed-size, non-executing file overlays. Original bytes are immutable; only
//! changed bytes and bounded transaction history are retained per edit.
mod assembly;
mod mapping;
pub use assembly::InstructionPreview;
pub use mapping::Mapping;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::Path,
    sync::Arc,
};

pub const MAX_PATCH_BYTES: usize = 1024 * 1024;
pub const MAX_HISTORY_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_TRANSACTIONS: usize = 4096;
pub const MAX_EDITS: usize = 256;
#[derive(Debug, thiserror::Error)]
#[error("patch error: {0}")]
pub struct PatchError(pub String);
pub type PatchResult<T> = Result<T, PatchError>;
impl From<std::io::Error> for PatchError {
    fn from(e: std::io::Error) -> Self {
        Self(e.to_string())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "space", content = "value", rename_all = "camelCase")]
pub enum Address {
    FileOffset(u64),
    VirtualAddress(u64),
    Rva(u64),
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Edit {
    pub offset: u64,
    pub before: Vec<u8>,
    pub after: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Transaction {
    pub id: u64,
    pub comment: String,
    pub kind: String,
    pub edits: Vec<Edit>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PatchState {
    #[serde(with = "hex_base")]
    pub raw_base: Option<u64>,
    pub raw_bitness: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_processor: Option<crate::processor::Processor>,
    pub version: u32,
    pub original_sha256: String,
    pub file_size: u64,
    pub transactions: Vec<Transaction>,
    pub cursor: usize,
    pub next_id: u64,
    pub revision: u64,
}
mod hex_base {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error> {
        match value {
            Some(v) => serializer.serialize_some(&format!("0x{v:X}")),
            None => serializer.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<u64>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|s| {
                u64::from_str_radix(s.strip_prefix("0x").unwrap_or(&s), 16)
                    .map_err(D::Error::custom)
            })
            .transpose()
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Preview {
    pub interpretation: String,
    pub schema_version: u32,
    pub original_sha256: String,
    pub revision: u64,
    pub edits: Vec<Edit>,
    pub kind: String,
    pub comment: String,
}
#[derive(Clone)]
pub struct PatchDocument {
    original: Arc<Vec<u8>>,
    state: PatchState,
    overlay: BTreeMap<u64, u8>,
    mappings: Vec<Mapping>,
    format: String,
    bitness: u32,
    instruction_supported: bool,
    protected: Vec<(u64, u64)>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Exported {
    pub schema_version: u32,
    pub bytes: u64,
    pub sha256: String,
    pub signature_warning: String,
}

impl PatchDocument {
    fn interpretation(&self) -> String {
        format!(
            "{}/{}/{:X?}",
            self.format,
            self.bitness,
            (self.state.raw_base, self.state.raw_processor)
        )
    }
    pub fn new(bytes: Vec<u8>) -> PatchResult<Self> {
        Self::from_shared(Arc::new(bytes))
    }
    pub fn from_shared(bytes: Arc<Vec<u8>>) -> PatchResult<Self> {
        use object::Object;
        let file = object::File::parse(bytes.as_slice()).map_err(|e| PatchError(e.to_string()))?;
        let instruction_supported = matches!(
            file.architecture(),
            object::Architecture::I386 | object::Architecture::X86_64
        );
        let (format, bitness, maps) = mapping::mappings(&bytes)?;
        let protected = mapping::protected(&bytes, &format)?;
        let mut doc = Self::create(bytes, format, bitness, maps)?;
        doc.instruction_supported = instruction_supported;
        doc.protected = protected;
        Ok(doc)
    }
    pub fn raw(bytes: Vec<u8>, base: Option<u64>, bitness: u32) -> PatchResult<Self> {
        Self::raw_shared(Arc::new(bytes), base, bitness)
    }
    pub fn raw_shared(bytes: Arc<Vec<u8>>, base: Option<u64>, bitness: u32) -> PatchResult<Self> {
        if !matches!(bitness, 32 | 64) {
            return Err(PatchError("raw processor mode must be 32 or 64".into()));
        }
        if bitness == 32
            && base.is_some_and(|a| {
                a.checked_add(bytes.len() as u64)
                    .is_none_or(|end| end > 1u64 << 32)
            })
        {
            return Err(PatchError(
                "raw mapping crosses the 32-bit address boundary".into(),
            ));
        }
        let mappings = match base {
            Some(address) if address.checked_add(bytes.len() as u64).is_some() => vec![Mapping {
                address,
                memory_size: bytes.len() as u64,
                file_offset: 0,
                file_size: bytes.len() as u64,
            }],
            Some(_) => return Err(PatchError("raw base range overflow".into())),
            None => vec![],
        };
        Self::create(bytes, "raw".into(), bitness, mappings)
    }
    fn create(
        bytes: Arc<Vec<u8>>,
        format: String,
        bitness: u32,
        mappings: Vec<Mapping>,
    ) -> PatchResult<Self> {
        if bytes.is_empty() || bytes.len() as u64 > crate::MAX_FILE_SIZE {
            return Err(PatchError("empty or oversized original file".into()));
        }
        let state = PatchState {
            raw_base: if format == "raw" {
                mappings.first().map(|m| m.address)
            } else {
                None
            },
            raw_bitness: if format == "raw" { Some(bitness) } else { None },
            raw_processor: None,
            version: 1,
            original_sha256: crate::sha256_hex(&bytes),
            file_size: bytes.len() as u64,
            transactions: vec![],
            cursor: 0,
            next_id: 1,
            revision: 0,
        };
        Ok(Self {
            original: bytes,
            state,
            overlay: BTreeMap::new(),
            mappings,
            format,
            bitness,
            instruction_supported: true,
            protected: vec![],
        })
    }
    pub fn raw_processor_shared(
        bytes: Arc<Vec<u8>>,
        base: Option<u64>,
        processor: crate::processor::Processor,
    ) -> PatchResult<Self> {
        let mut doc = Self::raw_shared(bytes, base, u32::from(processor.bits()))?;
        doc.state.raw_processor = Some(processor);
        doc.instruction_supported = processor.x86();
        Ok(doc)
    }
    pub fn state(&self) -> &PatchState {
        &self.state
    }
    pub fn original(&self) -> &[u8] {
        &self.original
    }
    pub fn mappings(&self) -> &[Mapping] {
        &self.mappings
    }
    pub fn bitness(&self) -> u32 {
        self.bitness
    }
    pub fn supports_assembly(&self) -> bool {
        self.instruction_supported
    }
    /// Compute once on a worker, not once per visible row/paint.
    pub fn revert_conflicts(&self) -> std::collections::BTreeSet<u64> {
        let mut covered: BTreeMap<u64, u64> = BTreeMap::new();
        let mut conflicts = std::collections::BTreeSet::new();
        for t in self.state.transactions[..self.state.cursor].iter().rev() {
            if t.edits.iter().any(|e| {
                covered
                    .range(..e.offset + e.after.len() as u64)
                    .next_back()
                    .is_some_and(|(_, &end)| end > e.offset)
            }) {
                conflicts.insert(t.id);
            }
            for e in &t.edits {
                let mut start = e.offset;
                let mut end = start + e.after.len() as u64;
                if let Some((&left, &right)) = covered.range(..=start).next_back() {
                    if right >= start {
                        start = left;
                        end = end.max(right);
                        covered.remove(&left);
                    }
                }
                while let Some((&left, &right)) = covered.range(start..).next() {
                    if left > end {
                        break;
                    }
                    end = end.max(right);
                    covered.remove(&left);
                }
                covered.insert(start, end);
            }
        }
        conflicts
    }
    pub fn format(&self) -> &str {
        &self.format
    }
    pub fn changed_bytes(&self) -> usize {
        self.overlay.len()
    }
    pub fn export_manifest(
        &self,
        destination: &Path,
        control: &dyn crate::AnalysisControl,
    ) -> PatchResult<Exported> {
        if control.is_cancelled() {
            return Err(PatchError("manifest export cancelled".into()));
        }
        let parent = std::fs::canonicalize(destination.parent().unwrap_or_else(|| Path::new(".")))?;
        let name = destination
            .file_name()
            .ok_or_else(|| PatchError("manifest destination needs a file name".into()))?;
        #[cfg(windows)]
        if name.to_string_lossy().contains(':') {
            return Err(PatchError(
                "alternate data stream destinations are not supported".into(),
            ));
        }
        let bytes =
            serde_json::to_vec_pretty(&self.state).map_err(|e| PatchError(e.to_string()))?;
        let mut temp = tempfile::NamedTempFile::new_in(&parent)?;
        temp.write_all(&bytes)?;
        temp.flush()?;
        temp.as_file().sync_all()?;
        if control.is_cancelled() {
            return Err(PatchError("manifest export cancelled".into()));
        }
        temp.persist_noclobber(parent.join(name))
            .map_err(|e| PatchError(e.error.to_string()))?;
        Ok(Exported {
            schema_version: 1,
            bytes: bytes.len() as u64,
            sha256: crate::sha256_hex(&bytes),
            signature_warning: "Patch metadata only; no inspected program was executed.".into(),
        })
    }
    pub fn offset(&self, address: Address, length: usize) -> PatchResult<u64> {
        if length == 0 || length > MAX_PATCH_BYTES {
            return Err(PatchError("patch/read length must be 1..=1 MiB".into()));
        }
        let offset = match address {
            Address::FileOffset(o) => o,
            Address::VirtualAddress(a) => mapping::translate(&self.mappings, a, length)?,
            Address::Rva(r) => {
                if self.format != "PE" {
                    return Err(PatchError("RVA addresses require PE".into()));
                }
                let base = self
                    .mappings
                    .first()
                    .ok_or_else(|| PatchError("missing PE headers".into()))?
                    .address;
                mapping::translate(
                    &self.mappings,
                    base.checked_add(r)
                        .ok_or_else(|| PatchError("RVA overflow".into()))?,
                    length,
                )?
            }
        };
        if offset
            .checked_add(length as u64)
            .is_none_or(|end| end > self.original.len() as u64)
        {
            return Err(PatchError("file range is outside original bytes".into()));
        }
        Ok(offset)
    }
    pub fn virtual_address(&self, offset: u64, length: usize) -> Option<u64> {
        let end = offset.checked_add(length as u64)?;
        let mut maps = self.mappings.iter().filter(|m| {
            offset >= m.file_offset && end <= m.file_offset.checked_add(m.file_size).unwrap_or(0)
        });
        let m = maps.next()?;
        if maps.next().is_some() {
            return None;
        }
        let address = m.address.checked_add(offset - m.file_offset)?;
        (mapping::translate(&self.mappings, address, length).ok() == Some(offset))
            .then_some(address)
    }
    pub fn read(&self, address: Address, length: usize) -> PatchResult<Vec<u8>> {
        let offset = self.offset(address, length)?;
        let mut bytes = self.original[offset as usize..offset as usize + length].to_vec();
        for (&position, &value) in self.overlay.range(offset..offset + length as u64) {
            bytes[(position - offset) as usize] = value;
        }
        Ok(bytes)
    }
    pub fn effective_binary(&self, path: &Path) -> crate::Result<crate::LoadedBinary> {
        if self.format == "raw" {
            crate::binary::analyze_raw_processor_bytes(
                path,
                self.materialize(),
                self.state.raw_base,
                self.state.raw_processor.unwrap_or(if self.bitness == 32 {
                    crate::processor::Processor::X86
                } else {
                    crate::processor::Processor::X86_64
                }),
            )
        } else {
            crate::binary::analyze_bytes(path, self.materialize())
        }
    }
    pub fn materialize(&self) -> Vec<u8> {
        let mut bytes = self.original.as_ref().clone();
        for (&offset, &value) in &self.overlay {
            bytes[offset as usize] = value;
        }
        bytes
    }
    /// The caller supplies current expected bytes: overlap is intentional only
    /// when all those bytes match. Edits within one transaction may not overlap.
    pub fn preview(
        &self,
        address: Address,
        expected: &[u8],
        replacement: &[u8],
        comment: &str,
    ) -> PatchResult<Preview> {
        let offset = self.offset(address, replacement.len())?;
        let preview = Preview {
            interpretation: self.interpretation(),
            schema_version: 1,
            original_sha256: self.state.original_sha256.clone(),
            revision: self.state.revision,
            edits: vec![Edit {
                offset,
                before: expected.to_vec(),
                after: replacement.to_vec(),
            }],
            kind: "bytes".into(),
            comment: comment.into(),
        };
        self.validate_preview(&preview)?;
        Ok(preview)
    }
    fn validate_edits(&self, edits: &[Edit], history_operation: bool) -> PatchResult<()> {
        let max_edits = if history_operation {
            MAX_PATCH_BYTES
        } else {
            MAX_EDITS
        };
        if edits.is_empty() || edits.len() > max_edits {
            return Err(PatchError(
                "transaction edit count is outside 1..=256".into(),
            ));
        }
        let mut ranges = Vec::new();
        let mut count = 0usize;
        for edit in edits {
            self.offset(Address::FileOffset(edit.offset), edit.after.len())?;
            if self.protected.iter().any(|&(start, end)| {
                edit.offset < end && start < edit.offset + edit.after.len() as u64
            }) {
                return Err(PatchError("format layout headers/tables are protected; executable restructuring is not supported".into()));
            }
            count = count
                .checked_add(edit.after.len())
                .ok_or_else(|| PatchError("transaction size overflow".into()))?;
            if edit.before.len() != edit.after.len()
                || self.read(Address::FileOffset(edit.offset), edit.before.len())? != edit.before
            {
                return Err(PatchError(
                    "stale expected bytes or unequal replacement length".into(),
                ));
            }
            ranges.push((edit.offset, edit.offset + edit.after.len() as u64));
        }
        ranges.sort_unstable();
        if count > MAX_PATCH_BYTES || ranges.windows(2).any(|w| w[0].1 > w[1].0) {
            return Err(PatchError(
                "oversized transaction or overlapping edits within transaction".into(),
            ));
        }
        Ok(())
    }
    fn validate_preview(&self, p: &Preview) -> PatchResult<()> {
        if p.interpretation != self.interpretation() {
            return Err(PatchError(
                "preview belongs to a different format, mode or raw base".into(),
            ));
        }
        if p.schema_version != 1 {
            return Err(PatchError("unsupported patch preview schema".into()));
        }
        if p.original_sha256 != self.state.original_sha256 || p.revision != self.state.revision {
            return Err(PatchError(
                "preview belongs to a different binary or revision".into(),
            ));
        }
        if p.comment.len() > 4096
            || !matches!(
                p.kind.as_str(),
                "bytes" | "instruction" | "revert" | "revertAll"
            )
        {
            return Err(PatchError("invalid patch metadata".into()));
        }
        self.validate_edits(&p.edits, matches!(p.kind.as_str(), "revert" | "revertAll"))
    }
    fn write_edits(&mut self, edits: &[Edit], forward: bool) {
        for e in edits {
            for (i, &value) in (if forward { &e.after } else { &e.before })
                .iter()
                .enumerate()
            {
                let offset = e.offset + i as u64;
                if self.original[offset as usize] == value {
                    self.overlay.remove(&offset);
                } else {
                    self.overlay.insert(offset, value);
                }
            }
        }
    }
    pub fn apply(&mut self, preview: &Preview) -> PatchResult<u64> {
        self.validate_preview(preview)?;
        let history_bytes: usize = self.state.transactions[..self.state.cursor]
            .iter()
            .flat_map(|t| &t.edits)
            .map(|e| e.before.len() + e.after.len())
            .sum();
        let new_bytes: usize = preview
            .edits
            .iter()
            .map(|e| e.before.len() + e.after.len())
            .sum();
        if self.state.cursor >= MAX_TRANSACTIONS || history_bytes + new_bytes > MAX_HISTORY_BYTES {
            return Err(PatchError("patch history resource limit reached".into()));
        }
        let mut overlay_size = self.overlay.len();
        for e in &preview.edits {
            for (i, &b) in e.after.iter().enumerate() {
                let o = e.offset + i as u64;
                let was = self.overlay.contains_key(&o);
                let will = b != self.original[o as usize];
                overlay_size = overlay_size + usize::from(will) - usize::from(was);
            }
        }
        if overlay_size > MAX_PATCH_BYTES
            || self.state.next_id == u64::MAX
            || self.state.revision == u64::MAX
        {
            return Err(PatchError("patch state resource limit reached".into()));
        }
        let id = self.state.next_id;
        self.write_edits(&preview.edits, true);
        self.state.transactions.truncate(self.state.cursor);
        self.state.transactions.push(Transaction {
            id,
            comment: preview.comment.clone(),
            kind: preview.kind.clone(),
            edits: preview.edits.clone(),
        });
        self.state.cursor += 1;
        self.state.next_id += 1;
        self.state.revision += 1;
        Ok(id)
    }
    pub fn undo(&mut self) -> PatchResult<()> {
        if self.state.cursor == 0 || self.state.revision == u64::MAX {
            return Err(PatchError("nothing to undo or revision exhausted".into()));
        }
        let edits = self.state.transactions[self.state.cursor - 1].edits.clone();
        self.write_edits(&edits, false);
        self.state.cursor -= 1;
        self.state.revision += 1;
        Ok(())
    }
    pub fn redo(&mut self) -> PatchResult<()> {
        if self.state.cursor >= self.state.transactions.len() || self.state.revision == u64::MAX {
            return Err(PatchError("nothing to redo or revision exhausted".into()));
        }
        let edits = self.state.transactions[self.state.cursor].edits.clone();
        self.validate_edits(
            &edits,
            matches!(
                self.state.transactions[self.state.cursor].kind.as_str(),
                "revert" | "revertAll"
            ),
        )?;
        self.write_edits(&edits, true);
        self.state.cursor += 1;
        self.state.revision += 1;
        Ok(())
    }
    pub fn revert(&mut self, id: u64) -> PatchResult<u64> {
        let index = self.state.transactions[..self.state.cursor]
            .iter()
            .position(|t| t.id == id)
            .ok_or_else(|| PatchError("patch ID is not currently applied".into()))?;
        let edits = &self.state.transactions[index].edits;
        if self.state.transactions[index + 1..self.state.cursor]
            .iter()
            .flat_map(|t| &t.edits)
            .any(|later| {
                edits.iter().any(|e| {
                    e.offset < later.offset + later.after.len() as u64
                        && later.offset < e.offset + e.after.len() as u64
                })
            })
        {
            return Err(PatchError(
                "later patches overlap this patch; undo them first".into(),
            ));
        }
        let p = Preview {
            interpretation: self.interpretation(),
            schema_version: 1,
            original_sha256: self.state.original_sha256.clone(),
            revision: self.state.revision,
            edits: edits
                .iter()
                .map(|e| Edit {
                    offset: e.offset,
                    before: e.after.clone(),
                    after: e.before.clone(),
                })
                .collect(),
            kind: "revert".into(),
            comment: format!("Revert patch {id}"),
        };
        self.apply(&p)
    }
    pub fn revert_all(&mut self) -> PatchResult<u64> {
        let mut edits: Vec<Edit> = Vec::new();
        for (&o, &b) in &self.overlay {
            if edits
                .last()
                .is_some_and(|last| last.offset + last.before.len() as u64 == o)
            {
                let last = edits.last_mut().unwrap();
                last.before.push(b);
                last.after.push(self.original[o as usize]);
            } else {
                edits.push(Edit {
                    offset: o,
                    before: vec![b],
                    after: vec![self.original[o as usize]],
                });
            }
        }
        self.apply(&Preview {
            interpretation: self.interpretation(),
            schema_version: 1,
            original_sha256: self.state.original_sha256.clone(),
            revision: self.state.revision,
            edits,
            kind: "revertAll".into(),
            comment: "Revert all changes".into(),
        })
    }
    /// Validate persisted history by replay, including the redo tail. No
    /// unchecked serialized overlay is ever trusted.
    pub fn restore(&mut self, state: &PatchState) -> PatchResult<()> {
        if state.version != 1
            || state.raw_base != self.state.raw_base
            || state.raw_bitness != self.state.raw_bitness
            || state.raw_processor != self.state.raw_processor
            || state.original_sha256 != self.state.original_sha256
            || state.file_size != self.original.len() as u64
            || state.cursor > state.transactions.len()
            || state.transactions.len() > MAX_TRANSACTIONS
        {
            return Err(PatchError(
                "patch state version, identity or history bounds mismatch".into(),
            ));
        }
        let mut verified = self.clone();
        verified.state.transactions.clear();
        verified.state.cursor = 0;
        verified.state.next_id = 1;
        verified.state.revision = 0;
        verified.overlay.clear();
        let mut last_id = 0;
        for t in &state.transactions {
            if t.id <= last_id {
                return Err(PatchError("patch IDs are not strictly increasing".into()));
            }
            verified.apply(&Preview {
                interpretation: self.interpretation(),
                schema_version: 1,
                original_sha256: state.original_sha256.clone(),
                revision: verified.state.revision,
                edits: t.edits.clone(),
                kind: t.kind.clone(),
                comment: t.comment.clone(),
            })?;
            last_id = t.id;
        }
        if state.next_id <= last_id
            || state.next_id == u64::MAX
            || state.revision < state.transactions.len() as u64
        {
            return Err(PatchError("invalid patch ID/revision counter".into()));
        }
        while verified.state.cursor > state.cursor {
            verified.undo()?;
        }
        verified.state = state.clone();
        *self = verified;
        Ok(())
    }
    /// New-file-only export; a temp file is verified and synced before atomic
    /// no-clobber publication. Cancellation never publishes a partial file.
    pub fn export(
        &self,
        source: &Path,
        destination: &Path,
        control: &dyn crate::AnalysisControl,
    ) -> PatchResult<Exported> {
        if control.is_cancelled() {
            return Err(PatchError("export cancelled".into()));
        }
        let source = std::fs::canonicalize(source)?;
        let source_file = std::fs::File::open(&source)?;
        if source_file.metadata()?.len() != self.state.file_size {
            return Err(PatchError("original file size changed on disk".into()));
        }
        let mut limited = source_file.take(self.state.file_size + 1);
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 65536];
        let mut count = 0u64;
        loop {
            if control.is_cancelled() {
                return Err(PatchError("export cancelled".into()));
            }
            let n = limited.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            count += n as u64;
            hasher.update(&buffer[..n]);
        }
        if count != self.state.file_size
            || format!("{:x}", hasher.finalize()) != self.state.original_sha256
        {
            return Err(PatchError("original file changed on disk".into()));
        }
        if destination.exists() {
            return Err(PatchError(
                "export destination already exists; choose a new filename".into(),
            ));
        }
        let parent = std::fs::canonicalize(destination.parent().unwrap_or_else(|| Path::new(".")))?;
        let name = destination
            .file_name()
            .ok_or_else(|| PatchError("destination has no file name".into()))?;
        #[cfg(windows)]
        if name.to_string_lossy().contains(':') {
            return Err(PatchError(
                "alternate data stream destinations are not supported".into(),
            ));
        }
        let destination = parent.join(name);
        if destination == source {
            return Err(PatchError("cannot export over the original file".into()));
        }
        let mut temp = tempfile::NamedTempFile::new_in(&parent)?;
        for (i, chunk) in self.original.chunks(65536).enumerate() {
            if control.is_cancelled() {
                return Err(PatchError("export cancelled".into()));
            }
            let offset = (i * 65536) as u64;
            let mut bytes = chunk.to_vec();
            for (&o, &b) in self.overlay.range(offset..offset + chunk.len() as u64) {
                bytes[(o - offset) as usize] = b;
            }
            temp.write_all(&bytes)?;
        }
        temp.flush()?;
        temp.as_file().sync_all()?;
        let mut file = std::fs::File::open(temp.path())?;
        if file.metadata()?.len() != self.state.file_size {
            return Err(PatchError("export size mismatch".into()));
        }
        let mut hasher = Sha256::new();
        for (i, chunk) in self.original.chunks(65536).enumerate() {
            if control.is_cancelled() {
                return Err(PatchError("export cancelled".into()));
            }
            let actual = &mut buffer[..chunk.len()];
            file.read_exact(actual)?;
            let offset = (i * 65536) as u64;
            let mut expected = chunk.to_vec();
            for (&o, &b) in self.overlay.range(offset..offset + chunk.len() as u64) {
                expected[(o - offset) as usize] = b;
            }
            if actual != expected {
                return Err(PatchError("export verification mismatch".into()));
            }
            hasher.update(actual);
        }
        if self.format != "raw" {
            crate::binary::analyze_path(temp.path())
                .map_err(|e| PatchError(format!("export re-import failed: {e}")))?;
        }
        let sha256 = format!("{:x}", hasher.finalize());
        if control.is_cancelled() {
            return Err(PatchError("export cancelled".into()));
        }
        temp.persist_noclobber(&destination)
            .map_err(|e| PatchError(e.error.to_string()))?;
        Ok(Exported {schema_version:1,bytes:self.state.file_size,sha256,signature_warning:"Modifications may invalidate code signatures and checksums; execution is not verified.".into()})
    }
}

pub fn parse_hex(text: &str) -> PatchResult<Vec<u8>> {
    if text.len() > MAX_PATCH_BYTES * 3 {
        return Err(PatchError("hex input too large".into()));
    }
    let compact: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if compact.is_empty()
        || compact.len() % 2 != 0
        || !compact.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(PatchError("enter complete hexadecimal byte pairs".into()));
    }
    (0..compact.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&compact[i..i + 2], 16).map_err(|e| PatchError(e.to_string())))
        .collect()
}
