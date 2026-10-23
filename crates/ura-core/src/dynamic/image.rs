//! Sparse known byte ranges, never a reconstructed portable executable.
use super::{
    cpu::{Config, Mapping},
    memory::{Memory, Permissions},
    *,
};
use crate::{CodeImage, CodeRegion, LoadedBinary};
use serde_json::{json, Value};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Segment {
    pub base: Address,
    pub bytes: Vec<u8>,
    pub permissions: Permissions,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Image {
    pub format: String,
    pub schema_version: u32,
    pub bitness: u8,
    pub provenance: String,
    pub segments: Vec<Segment>,
    pub missing: Vec<(Address, u64)>,
    pub original_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_metadata: Option<Value>,
}
impl Image {
    pub fn validate(&self) -> Result<()> {
        if self.format != "ura-memory-image"
            || self.schema_version != 1
            || self.provenance.len() > 1024
            || self
                .capture_metadata
                .as_ref()
                .is_some_and(|v| serde_json::to_vec(v).map_or(true, |b| b.len() > 65536))
            || self.segments.len() > 256
            || self.missing.len() > 256
            || self
                .original_sha256
                .as_ref()
                .is_some_and(|h| h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(Fault::new(
                "imageFormat",
                0,
                "invalid image version, metadata or region count",
            ));
        }
        let mut memory = Memory::new(self.bitness, 16 * 1024 * 1024)?;
        for s in &self.segments {
            memory.map(
                s.base.0,
                s.bytes.len(),
                &s.bytes,
                s.permissions,
                "known image bytes",
            )?;
        }
        for (index, (a, len)) in self.missing.iter().enumerate() {
            if *len == 0
                || a.0.checked_add(*len).is_none()
                || self.bitness == 32 && a.0 + len > 1u64 << 32
                || self.missing[..index]
                    .iter()
                    .any(|(b, n)| a.0 < b.0 + n && b.0 < a.0 + len)
                || self
                    .segments
                    .iter()
                    .any(|s| a.0 < s.base.0 + s.bytes.len() as u64 && s.base.0 < a.0 + len)
            {
                return Err(Fault::new(
                    "imageFormat",
                    a.0,
                    "missing range overlaps known bytes or overflows",
                ));
            }
        }
        Ok(())
    }
    pub fn load(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 16 * 1024 * 1024 {
            return Err(Fault::new("limit", 0, "image JSON exceeds16MiB"));
        }
        let v: Value = serde_json::from_slice(bytes)
            .map_err(|e| Fault::new("imageFormat", 0, e.to_string()))?;
        if v["format"] == "ura-memory-image" {
            let image: Self = serde_json::from_value(v)
                .map_err(|e| Fault::new("imageFormat", 0, e.to_string()))?;
            image.validate()?;
            return Ok(image);
        }
        if v["format"] != "ura-memory-snapshot" || v["schemaVersion"] != 1 {
            return Err(Fault::new(
                "imageFormat",
                0,
                "expected v1 memory snapshot/image",
            ));
        }
        let parse = |v: &Value| {
            v.as_str()
                .and_then(|s| crate::parse_address(s).ok())
                .ok_or_else(|| Fault::new("imageFormat", 0, "address strings required"))
        };
        let base = parse(&v["address"])?;
        let length = v["requested"]
            .as_u64()
            .filter(|n| *n > 0 && *n <= 1024 * 1024)
            .ok_or_else(|| {
                Fault::new(
                    "imageFormat",
                    base,
                    "snapshot requested range outside1..1MiB",
                )
            })?;
        let end = base
            .checked_add(length)
            .ok_or_else(|| Fault::new("imageFormat", base, "snapshot range overflow"))?;
        let chunks = v["chunks"]
            .as_array()
            .filter(|a| a.len() <= 257)
            .ok_or_else(|| Fault::new("imageFormat", base, "bounded chunks required"))?;
        let mut image = Self {
            format: "ura-memory-image".into(),
            schema_version: 1,
            bitness: 64,
            provenance: "Imported observed snapshot; CPU mode assumed x64 (legacy capture has no architecture); missing bytes remain unmapped".into(),
            segments: vec![],
            missing: vec![],
            original_sha256: None,
            capture_metadata:Some(json!({"mode":"observed","session":v["session"],"pid":v["pid"],"captureEventSequence":v["captureEventSequence"],"elapsedMicros":v["elapsedMicros"],"modules":v["modules"],"hashScope":v["hashScope"],"metadataTrust":"Imported evidence; not independently verified runtime identity"})),
        };
        let mut ranges = vec![];
        let mut captured = vec![];
        for c in chunks {
            let address = parse(&c["address"])?;
            let requested = c["requested"].as_u64().ok_or_else(|| {
                Fault::new("imageFormat", address, "chunk requested length required")
            })?;
            let data: Vec<u8> = serde_json::from_value(c["bytes"].clone())
                .map_err(|e| Fault::new("imageFormat", address, e.to_string()))?;
            let stop = address
                .checked_add(requested)
                .filter(|n| *n <= end)
                .ok_or_else(|| Fault::new("imageFormat", address, "chunk overflow"))?;
            if address < base
                || ranges.last().is_some_and(|&(_, last)| address < last)
                || requested == 0
                || data.len() as u64 > requested
                || c["missing"].as_u64() != Some(requested - data.len() as u64)
                || ranges.iter().any(|&(a, b)| address < b && a < stop)
            {
                return Err(Fault::new(
                    "imageFormat",
                    address,
                    "overlap, missing-size or out-of-range chunk",
                ));
            }
            ranges.push((address, stop));
            captured.extend_from_slice(&data);
            if !data.is_empty() {
                let protection = c["region"]["protection"].as_u64().unwrap_or(0);
                image.segments.push(Segment {
                    base: Address(address),
                    bytes: data,
                    permissions: Permissions {
                        read: true,
                        write: protection & 0xcc != 0,
                        execute: protection & 0xf0 != 0,
                    },
                });
            }
        }
        image.segments.sort_by_key(|s| s.base);
        let mut cursor = base;
        for s in &image.segments {
            if s.base.0 > cursor {
                image.missing.push((Address(cursor), s.base.0 - cursor));
            }
            cursor = s.base.0 + s.bytes.len() as u64;
        }
        if cursor < end {
            image.missing.push((Address(cursor), end - cursor));
        }
        if v["captured"].as_u64() != Some(captured.len() as u64)
            || v["missing"].as_u64() != Some(length - captured.len() as u64)
            || v["capturedBytesSha256"].as_str() != Some(crate::sha256_hex(&captured).as_str())
        {
            return Err(Fault::new(
                "imageFormat",
                base,
                "snapshot byte count/hash mismatch",
            ));
        }
        image.validate()?;
        Ok(image)
    }
    pub fn from_binary(binary: &LoadedBinary) -> Result<Self> {
        let a = binary.analysis();
        if !matches!(a.format.as_str(), "PE" | "ELF" | "raw")
            || a.endianness != crate::binary::Endianness::Little
            || !matches!(
                (a.architecture, a.bitness),
                (crate::binary::CpuArchitecture::X86, 32)
                    | (crate::binary::CpuArchitecture::X86_64, 64)
            )
        {
            return Err(Fault::new(
                "loader",
                0,
                "only preferred-address PE/ELF and explicit raw x86/x64 supported",
            ));
        }
        let mut image = Self {
            format: "ura-memory-image".into(),
            schema_version: 1,
            bitness: a.bitness,
            provenance: format!(
                "{} preferred virtual addresses; no relocation, dynamic linking or OS loader",
                a.format
            ),
            segments: vec![],
            missing: vec![],
            original_sha256: Some(crate::sha256_hex(binary.bytes())),
            capture_metadata: None,
        };
        if a.format == "ELF" {
            use object::{Object, ObjectSegment, SegmentFlags};
            let file = object::File::parse(binary.bytes())
                .map_err(|e| Fault::new("loader", 0, e.to_string()))?;
            let segments = file
                .segments()
                .filter(|s| s.size() != 0)
                .collect::<Vec<_>>();
            let total = segments
                .iter()
                .try_fold(0u64, |n, s| n.checked_add(s.size()));
            if segments.len() > 256 || total.map_or(true, |n| n > 16 * 1024 * 1024) {
                return Err(Fault::new(
                    "memoryBudget",
                    0,
                    "ELF segment budget exceeded before allocation",
                ));
            }
            for segment in segments {
                let data = segment
                    .data()
                    .map_err(|e| Fault::new("loader", segment.address(), e.to_string()))?;
                if data.len() as u64 > segment.size() {
                    return Err(Fault::new(
                        "loader",
                        segment.address(),
                        "ELF filesz exceeds memsz",
                    ));
                }
                let mut bytes = data.to_vec();
                bytes.resize(segment.size() as usize, 0);
                let SegmentFlags::Elf { p_flags } = segment.flags() else {
                    return Err(Fault::new(
                        "loader",
                        segment.address(),
                        "ELF segment flags unavailable",
                    ));
                };
                image.segments.push(Segment {
                    base: Address(segment.address()),
                    bytes,
                    permissions: Permissions {
                        read: p_flags & 4 != 0,
                        write: p_flags & 2 != 0,
                        execute: p_flags & 1 != 0,
                    },
                });
            }
            image.validate()?;
            return Ok(image);
        }
        let allocated = a
            .sections
            .iter()
            .filter(|s| s.readable || s.writable || s.executable)
            .try_fold(0u64, |sum, s| sum.checked_add(s.size));
        if allocated.map_or(true, |n| n > 16 * 1024 * 1024) || a.sections.len() > 256 {
            return Err(Fault::new(
                "memoryBudget",
                0,
                "image aggregate mapping budget exceeded before allocation",
            ));
        }
        for section in &a.sections {
            if section.size == 0 || !section.readable && !section.writable && !section.executable {
                continue;
            }
            if section.size > 16 * 1024 * 1024 {
                return Err(Fault::new(
                    "memoryBudget",
                    section.address,
                    "section exceeds16MiB",
                ));
            }
            let mut bytes = if let Some(offset) = section.file_offset {
                let n = section.file_size.min(section.size) as usize;
                binary
                    .bytes()
                    .get(
                        offset as usize..(offset as usize).checked_add(n).ok_or_else(|| {
                            Fault::new("loader", section.address, "file range overflow")
                        })?,
                    )
                    .ok_or_else(|| {
                        Fault::new("loader", section.address, "section file bytes missing")
                    })?
                    .to_vec()
            } else {
                vec![]
            };
            bytes.resize(section.size as usize, 0);
            image.segments.push(Segment {
                base: Address(section.address),
                bytes,
                permissions: Permissions {
                    read: section.readable,
                    write: section.writable,
                    execute: section.executable,
                },
            });
        }
        image.validate()?;
        Ok(image)
    }
    pub fn config(&self, entry: u64, mut config: Config) -> Result<Config> {
        self.validate()?;
        if !config.mappings.is_empty() {
            return Err(Fault::new(
                "configuration",
                entry,
                "image loading and explicit mappings cannot overlap implicitly",
            ));
        }
        config.bitness = self.bitness;
        config.entry = Address(entry);
        config.mappings = self
            .segments
            .iter()
            .map(|s| Mapping {
                base: s.base,
                bytes: s.bytes.clone(),
                size: s.bytes.len(),
                permissions: s.permissions,
            })
            .collect();
        Ok(config)
    }
    pub fn read(&self, address: u64, length: usize) -> Result<Vec<u8>> {
        let mut m = Memory::new(self.bitness, 16 * 1024 * 1024)?;
        for s in &self.segments {
            m.map(
                s.base.0,
                s.bytes.len(),
                &s.bytes,
                s.permissions,
                "captured known range",
            )?;
        }
        m.read(address, length)
    }
    pub fn compare(&self, other: &Self, address: u64, length: usize) -> Result<Value> {
        if length > 65536 || address.checked_add(length as u64).is_none() {
            return Err(Fault::new(
                "limit",
                address,
                "comparison1..64KiB, no overflow",
            ));
        }
        let mut changes = vec![];
        let mut compared = 0;
        let mut changed = 0;
        let mut unknown = 0;
        for n in 0..length {
            let a = address + n as u64;
            let get = |image: &Self| {
                image.segments.iter().find_map(|s| {
                    a.checked_sub(s.base.0)
                        .and_then(|o| s.bytes.get(o as usize).copied())
                })
            };
            match (get(self), get(other)) {
                (Some(a0), Some(b0)) => {
                    compared += 1;
                    if a0 != b0 {
                        changed += 1;
                        if changes.len() < 256 {
                            changes.push(json!({"address":Address(a),"before":a0,"after":b0}));
                        }
                    }
                }
                _ => unknown += 1,
            }
        }
        Ok(
            json!({"mode":"capturedImageComparison","comparedBytes":compared,"changedBytes":changed,"unknownBytes":unknown,"changes":changes,"cause":"Unknown; byte differences alone do not prove relocation, patching or runtime-write cause"}),
        )
    }
    pub fn analyze(&self, entry: u64) -> Result<Value> {
        self.validate()?;
        let exec = CodeImage::new(
            self.segments
                .iter()
                .filter(|s| s.permissions.execute)
                .map(|s| CodeRegion {
                    start: s.base.0,
                    bytes: &s.bytes,
                })
                .collect(),
        );
        let options = crate::AnalysisOptions {
            max_instructions: 5000,
            max_functions: 256,
            max_blocks: 2048,
            ..Default::default()
        };
        let analysis = crate::analyze_image(&exec, self.bitness, Some(entry), &[], &options, &());
        let ir =
            crate::ir::lift_image(&exec, self.bitness, &analysis, entry, &()).and_then(|raw| {
                let ssa = crate::ir::ssa::construct(&raw)?;
                Ok(json!({"raw":raw,"ssa":ssa}))
            });
        let segment = self
            .segments
            .iter()
            .find(|s| {
                s.permissions.execute
                    && entry >= s.base.0
                    && entry - s.base.0 < s.bytes.len() as u64
            })
            .ok_or_else(|| {
                Fault::new(
                    "entry",
                    entry,
                    "selected entry is not known executable bytes",
                )
            })?;
        let binary = crate::binary::analyze_raw_bytes(
            std::path::Path::new("captured-memory.raw"),
            segment.bytes.clone(),
            Some(segment.base.0),
            u32::from(self.bitness),
        )
        .map_err(|e| Fault::new("analysis", entry, e.to_string()))?;
        let local = crate::analyze_image(
            &CodeImage::from_binary(&binary),
            self.bitness,
            Some(entry),
            &[],
            &options,
            &(),
        );
        let pseudocode = crate::decomp::analyze_function(
            &binary,
            &local,
            entry,
            &crate::decomp::DecompContext::new(u16::from(self.bitness)),
            &(),
        )
        .map(|v| v.pseudocode);
        Ok(
            json!({"mode":"capturedMemoryAnalysis","entry":Address(entry),"provenance":self.provenance,"missing":self.missing,"portableExecutableReconstructed":false,"report":analysis.report,"functions":analysis.functions.iter().map(|f|json!({"address":Address(f.address),"end":Address(f.end),"blocks":f.blocks.len()})).collect::<Vec<_>>(),"blocks":analysis.blocks.values().map(|b|json!({"address":Address(b.address),"instructions":b.instructions.iter().copied().map(Address).collect::<Vec<_>>(),"successors":b.successors.iter().map(|e|json!({"target":Address(e.target),"kind":format!("{:?}",e.kind)})).collect::<Vec<_>>()})).collect::<Vec<_>>(),"ir":ir.as_ref().ok(),"irError":ir.as_ref().err(),"pseudocode":pseudocode.as_ref().ok(),"pseudocodeError":pseudocode.as_ref().err(),"pseudocodeScope":"selected contiguous known executable range; sparse cross-range reconstruction remains partial"}),
        )
    }
}
