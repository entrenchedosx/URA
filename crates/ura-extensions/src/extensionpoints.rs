//! Untrusted decoder descriptions are validated before entering shared engines.
use crate::{
    bridge::{number, required},
    invalid,
    runtime::read_bounded,
    ExtensionHost, Result,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use ura_core::{
    format_address, parse_address, DecodedInstruction, InstructionFlow, ProgramAnalysis,
};
#[derive(Clone)]
pub(crate) struct Source {
    pub kind: String,
    pub plugin: String,
    pub digest: String,
    pub path: PathBuf,
    pub bytes: Vec<u8>,
    pub base: u64,
}
pub(crate) struct ProcessorImage {
    analysis: Arc<ProgramAnalysis>,
    source_sha: String,
    plugin: String,
    registers: Vec<String>,
    selected: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Loader {
    processor: String,
    entry: String,
    segments: Vec<Segment>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Segment {
    address: String,
    file_offset: usize,
    size: usize,
    permissions: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Processor {
    processor: String,
    entry: String,
    endianness: String,
    address_bits: u8,
    registers: Vec<String>,
    instructions: Vec<Instruction>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Instruction {
    address: String,
    length: u8,
    mnemonic: String,
    #[serde(default)]
    operands: String,
    flow: String,
    target: Option<String>,
    #[serde(default)]
    invalid: bool,
}
impl ExtensionHost {
    pub(crate) fn prepare_source(
        &self,
        p: &mut Value,
        plugin: &crate::plugins::Installed,
    ) -> Result<Source> {
        let policy = self
            .inner
            .service
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extension_policy();
        let path = policy
            .allow_read(Path::new(required(p, "path")?))
            .map_err(|e| e.to_string())?;
        let bytes = read_bounded(&path, 65536)?;
        if bytes.is_empty() {
            return invalid("Extension input is empty");
        }
        let base = p["base"]
            .as_str()
            .map(parse_address)
            .transpose()
            .map_err(|e| e.to_string())?
            .unwrap_or(0);
        if base.checked_add(bytes.len() as u64).is_none() {
            return invalid("Extension input address overflow");
        }
        p["parameters"] = json!({"bytesHex":bytes.iter().map(|b|format!("{b:02x}")).collect::<String>(),"base":format_address(base),"fileSize":bytes.len(),"sha256":ura_core::sha256_hex(&bytes)});
        Ok(Source {
            kind: required(p, "kind")?.into(),
            plugin: plugin.manifest.id.clone(),
            digest: plugin.digest.clone(),
            path,
            bytes,
            base,
        })
    }
    pub(crate) fn accept_extension(&self, p: &Value) -> Result<Value> {
        self.enabled()?;
        let id = required(p, "job")?;
        let result = self.job(id)?;
        if result["state"] != "complete" {
            return invalid("Only a successful extension callback can be accepted");
        }
        let source = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sources
            .get(id)
            .cloned()
            .ok_or("Job is not a loader/processor callback")?;
        let plugin = self.inner.registry.inspect(&source.plugin)?;
        if !plugin.enabled || plugin.digest != source.digest {
            return invalid("Extension was disabled or changed");
        }
        let cap = if source.kind == "loader" {
            "loader.register"
        } else {
            "processor.register"
        };
        if !self.inner.config.capabilities.contains(cap)
            || !plugin.grants.is_some_and(|g| g.capabilities.contains(cap))
        {
            return invalid("Extension grant revoked");
        }
        let sha = ura_core::sha256_hex(&source.bytes);
        if source.kind == "loader" {
            let model: Loader =
                serde_json::from_value(result["value"].clone()).map_err(|e| e.to_string())?;
            let processor = ura_core::processor::Processor::parse(&model.processor).ok_or(
                "Unsupported loader processor; use a processor extension for a custom ISA",
            )?;
            if model.segments.is_empty() || model.segments.len() > 32 {
                return invalid("Loader requires1..32 file-backed segments");
            }
            let mut segments = Vec::new();
            let mut total = 0usize;
            for s in model.segments {
                total = total.checked_add(s.size).ok_or("Loader size overflow")?;
                if total > 65536 || s.size == 0 {
                    return invalid("Loader expanded byte limit");
                }
                let end = s
                    .file_offset
                    .checked_add(s.size)
                    .ok_or("File offset overflow")?;
                let bytes = source
                    .bytes
                    .get(s.file_offset..end)
                    .ok_or("Loader segment outside immutable input")?
                    .to_vec();
                let permissions = match s.permissions.as_str() {
                    "r" => ura_core::dynamic::memory::Permissions {
                        read: true,
                        write: false,
                        execute: false,
                    },
                    "rx" => ura_core::dynamic::memory::Permissions {
                        read: true,
                        write: false,
                        execute: true,
                    },
                    "rw" => ura_core::dynamic::memory::Permissions {
                        read: true,
                        write: true,
                        execute: false,
                    },
                    _ => return invalid("Loader segment permissions require r/rx/rw"),
                };
                segments.push(ura_core::dynamic::image::Segment {
                    base: ura_core::ir::Address(
                        parse_address(&s.address).map_err(|e| e.to_string())?,
                    ),
                    bytes,
                    permissions,
                });
            }
            let entry = parse_address(&model.entry).map_err(|e| e.to_string())?;
            if !segments.iter().any(|s| {
                s.permissions.execute
                    && entry >= s.base.0
                    && s.base
                        .0
                        .checked_add(s.bytes.len() as u64)
                        .is_some_and(|end| entry < end)
            }) {
                return invalid("Loader entry must be inside executable known bytes");
            }
            let image = ura_core::dynamic::image::Image {
                format: "ura-memory-image".into(),
                schema_version: 1,
                bitness: processor.bits(),
                processor: Some(processor),
                provenance: format!(
                    "Loader plugin {}@{}; file-backed custom container; NOT an OS executable",
                    source.plugin, plugin.manifest.version
                ),
                segments,
                missing: vec![],
                original_sha256: Some(sha),
                capture_metadata: Some(
                    json!({"source":source.path,"pluginDigest":source.digest,"entry":model.entry}),
                ),
            };
            image.validate().map_err(|e| e.to_string())?;
            let mut service = self.inner.service.lock().unwrap_or_else(|e| e.into_inner());
            let loaded = service
                .dynamic
                .insert_image(image)
                .map_err(|e| e.to_string())?;
            let analysis=service.dynamic_rpc(json!({"operation":"image","action":"analyze","handle":loaded["handle"],"entry":model.entry})).map_err(|e|e.to_string())?;
            Ok(
                json!({"kind":"loader","image":loaded["handle"],"entry":model.entry,"analysis":analysis,"provenance":"file bytes -> validated plugin mapping -> existing core memory-image analysis"}),
            )
        } else {
            let model: Processor =
                serde_json::from_value(result["value"].clone()).map_err(|e| e.to_string())?;
            if model.processor != "toy8"
                || model.endianness != "little"
                || ![8, 16, 32, 64].contains(&model.address_bits)
                || model.registers.is_empty()
                || model.registers.len() > 32
                || model.registers.iter().any(|r| {
                    r.is_empty()
                        || r.len() > 32
                        || !r.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                })
            {
                return invalid("Unsupported processor description");
            }
            if model.address_bits < 64
                && source.base + source.bytes.len() as u64 > 1u64 << model.address_bits
            {
                return invalid("Processor input exceeds address width");
            }
            let mut cursor = source.base;
            let mut decoded = Vec::new();
            for i in model.instructions {
                let address = parse_address(&i.address).map_err(|e| e.to_string())?;
                let end = address
                    .checked_add(u64::from(i.length))
                    .ok_or("Instruction address overflow")?;
                if address != cursor || end > source.base + source.bytes.len() as u64 {
                    return invalid("Decoder must cover input in order without gaps/overlaps");
                }
                cursor = end;
                let flow = match i.flow.as_str() {
                    "next" => InstructionFlow::Next,
                    "jump" => InstructionFlow::Jump,
                    "conditionalJump" => InstructionFlow::ConditionalJump,
                    "return" => InstructionFlow::Return,
                    "call" => InstructionFlow::Call,
                    "indirectJump" => InstructionFlow::IndirectJump,
                    "indirectCall" => InstructionFlow::IndirectCall,
                    _ => return invalid("Unsupported flow classification"),
                };
                decoded.push(DecodedInstruction {
                    address,
                    length: i.length,
                    flow,
                    target: i
                        .target
                        .as_deref()
                        .map(parse_address)
                        .transpose()
                        .map_err(|e| e.to_string())?,
                    data_references: vec![],
                    invalid: i.invalid,
                    mnemonic: i.mnemonic,
                    operands: i.operands,
                });
            }
            if cursor != source.base + source.bytes.len() as u64 {
                return invalid("Decoder did not cover all input bytes");
            }
            let entry = parse_address(&model.entry).map_err(|e| e.to_string())?;
            let analysis = ura_core::analysis::analyze_extension_instructions(decoded, entry)?;
            let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.processors.len() >= 4 {
                return invalid("At most four processor images; close one");
            }
            let handle = format!(
                "processor-{}",
                self.inner
                    .next
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            );
            let report = analysis.report.clone();
            state.processors.insert(
                handle.clone(),
                ProcessorImage {
                    analysis: Arc::new(analysis),
                    source_sha: sha,
                    plugin: source.plugin,
                    registers: model.registers,
                    selected: entry,
                },
            );
            Ok(
                json!({"kind":"processor","handle":handle,"processor":"toy8","entry":format_address(entry),"report":report,"capabilities":{"disassembly":true,"navigation":true,"cfg":true,"ir":false,"ssa":false,"decompilation":false,"emulation":false,"symbolic":false}}),
            )
        }
    }
    pub(crate) fn processor_rpc(&self, action: &str, p: &Value) -> Result<Value> {
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        let id = required(p, "handle")?;
        if action == "close" {
            state
                .processors
                .remove(id)
                .ok_or("Unknown processor image")?;
            return Ok(json!({"closed":true}));
        }
        let image = state
            .processors
            .get_mut(id)
            .ok_or("Unknown processor image")?;
        if let Some(a) = p["address"].as_str() {
            let a = parse_address(a).map_err(|e| e.to_string())?;
            if !image.analysis.instructions.contains_key(&a) {
                return invalid("Processor navigation requires a decoded address");
            }
            image.selected = a;
        }
        let limit = number(p, "limit", 64, 256)?;
        if action != "page" {
            return invalid("Custom processors currently support page/close; IR and execution require a future semantic provider");
        }
        let instructions=image.analysis.instructions.range(image.selected..).take(limit).map(|(_,i)|json!({"address":format_address(i.address),"length":i.length,"mnemonic":i.mnemonic,"operands":i.operands,"flow":i.flow.name(),"target":i.target.map(format_address),"invalid":i.invalid})).collect::<Vec<_>>();
        let blocks=image.analysis.blocks.values().take(256).map(|b|json!({"address":format_address(b.address),"instructions":b.instructions.iter().map(|a|format_address(*a)).collect::<Vec<_>>(),"successors":b.successors.iter().map(|e|json!({"target":format_address(e.target),"kind":e.kind.name()})).collect::<Vec<_>>()})).collect::<Vec<_>>();
        Ok(
            json!({"handle":id,"sourceSha256":image.source_sha,"plugin":image.plugin,"registers":image.registers,"selected":format_address(image.selected),"instructions":instructions,"blocks":blocks,"report":image.analysis.report,"provenance":"plugin decoder claims; validated boundaries; CFG from shared Rust core"}),
        )
    }
}
