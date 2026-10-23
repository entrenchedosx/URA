//! Indexed browsing of imported observations. No execution or invented memory.
use super::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;
#[derive(Clone, Debug)]
struct Record {
    sequence: u64,
    thread: u32,
    address: Option<u64>,
    sample_ip: Option<u64>,
    kind: String,
    registers: BTreeMap<String, Option<u64>>,
    module: Option<Module>,
    epoch: u64,
    raw: Value,
}
#[derive(Clone, Debug)]
struct Module {
    base: u64,
    size: u64,
    sha: Option<String>,
    rva: u64,
}
#[derive(Clone, Default)]
struct RegisterPoint {
    values: BTreeMap<String, Option<u64>>,
    sequence: u64,
    epoch: u64,
    ip: Option<u64>,
}
#[derive(Default)]
struct ThreadIndex {
    positions: Vec<usize>,
    checkpoints: Vec<RegisterPoint>,
}
pub struct Replay {
    records: Vec<Record>,
    threads: BTreeMap<u32, ThreadIndex>,
    pub mode: String,
    pub dropped: u64,
    pub bytes: usize,
}
fn err(message: &str) -> Fault {
    Fault::new("traceFormat", 0, message)
}
fn number(v: &Value) -> Result<u64> {
    v.as_str()
        .ok_or_else(|| err("addresses/registers must be hexadecimal strings"))
        .and_then(|s| crate::parse_address(s).map_err(|_| err("invalid address/register value")))
}
fn sha(v: &str) -> bool {
    v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit())
}
impl Replay {
    pub fn load(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 16 * 1024 * 1024 {
            return Err(err("trace import exceeds16MiB"));
        }
        let value: Value = serde_json::from_slice(bytes).map_err(|e| err(&e.to_string()))?;
        if value["schemaVersion"] != 1 {
            return Err(err("trace schemaVersion1 required"));
        }
        let emulated = match value["format"].as_str() {
            Some("ura-observed-trace") => false,
            Some("ura-emulation-trace") => true,
            _ => return Err(err("unsupported trace format")),
        };
        if !emulated
            && (value["session"]
                .as_str()
                .map_or(true, |s| s.is_empty() || s.len() > 128)
                || value["pid"]
                    .as_u64()
                    .map_or(true, |n| n == 0 || n > u32::MAX as u64))
        {
            return Err(err(
                "bounded nonempty session and positive 32-bit pid required",
            ));
        }
        let bits = if value["bitness"].is_null() {
            64
        } else {
            value["bitness"]
                .as_u64()
                .filter(|b| matches!(b, 32 | 64))
                .ok_or_else(|| err("bitness must be32 or64"))?
        };
        let events = value["events"]
            .as_array()
            .ok_or_else(|| err("events array required"))?;
        if events.len() > 10000 {
            return Err(err("at most10000 trace events"));
        }
        let dropped = if emulated {
            value["dropped"].as_u64().unwrap_or(0)
        } else {
            value["summary"]["dropped"].as_u64().unwrap_or(0)
        };
        let mut result = Self {
            records: vec![],
            threads: BTreeMap::new(),
            mode: if emulated { "emulated" } else { "observed" }.into(),
            dropped,
            bytes: bytes.len(),
        };
        let mut previous = 0;
        let mut epoch = 0;
        let mut banks: BTreeMap<u32, RegisterPoint> = BTreeMap::new();
        for event in events {
            if serde_json::to_vec(event)
                .map_err(|_| err("invalid event"))?
                .len()
                > 65536
            {
                return Err(err("event exceeds64KiB"));
            }
            let sequence = event["sequence"]
                .as_u64()
                .filter(|s| *s > previous)
                .ok_or_else(|| {
                    err("event sequence must be strictly increasing positive integers")
                })?;
            if previous != 0 && sequence != previous + 1 {
                epoch += 1;
            }
            previous = sequence;
            let thread = if emulated {
                0
            } else {
                u32::try_from(
                    event["thread"]
                        .as_u64()
                        .ok_or_else(|| err("thread required"))?,
                )
                .map_err(|_| err("thread outside32bits"))?
            };
            if !emulated && (event["session"] != value["session"] || event["pid"] != value["pid"]) {
                return Err(err("mixed trace session/process identities"));
            }
            let kind = if emulated {
                "instruction".to_string()
            } else {
                event["kind"]
                    .as_str()
                    .filter(|s| s.len() <= 128)
                    .ok_or_else(|| err("bounded event kind required"))?
                    .to_string()
            };
            let address = if event["address"].is_null() {
                None
            } else {
                Some(number(&event["address"])?)
            };
            if kind == "instruction" && address.is_none() {
                return Err(err("instruction event address required"));
            }
            let sample_ip = if emulated {
                Some(number(&event["nextAddress"])?)
            } else {
                address
            };
            if bits == 32
                && (address.is_some_and(|a| a > u32::MAX as u64)
                    || sample_ip.is_some_and(|a| a > u32::MAX as u64))
            {
                return Err(err("instruction address exceeds architecture width"));
            }
            let changes = if emulated {
                &event["changedRegisters"]
            } else {
                &event["detail"]["changedRegisters"]
            };
            let mut registers = BTreeMap::new();
            if let Some(changes) = changes.as_object() {
                if changes.len() > 64 {
                    return Err(err("at most64 changed registers/event"));
                }
                for (k, v) in changes {
                    if k.is_empty()
                        || k.len() > 32
                        || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    {
                        return Err(err("invalid register name"));
                    }
                    registers.insert(k.clone(), if v.is_null() { None } else { Some(number(v)?) });
                }
            } else if !changes.is_null() {
                return Err(err("changed registers must be an object"));
            }
            let module = if event["module"].is_null() {
                None
            } else {
                let m = &event["module"];
                let base = number(&m["base"])?;
                let rva = number(&m["rva"])?;
                let size = m["size"]
                    .as_u64()
                    .filter(|s| *s > 0)
                    .ok_or_else(|| err("module size required"))?;
                if rva >= size
                    || base.checked_add(size).is_none()
                    || address != base.checked_add(rva)
                {
                    return Err(err("module/RVA/address inconsistency"));
                }
                let hash = if m["sha256"].is_null() {
                    None
                } else {
                    Some(
                        m["sha256"]
                            .as_str()
                            .filter(|s| sha(s))
                            .ok_or_else(|| err("invalid module hash"))?
                            .to_ascii_lowercase(),
                    )
                };
                Some(Module {
                    base,
                    size,
                    sha: hash,
                    rva,
                })
            };
            let i = result.records.len();
            result.records.push(Record {
                sequence,
                thread,
                address,
                sample_ip,
                kind: kind.clone(),
                registers: registers.clone(),
                module,
                epoch,
                raw: event.clone(),
            });
            if kind == "instruction" {
                if !result.threads.contains_key(&thread) && result.threads.len() >= 64 {
                    return Err(err("at most64 traced instruction threads"));
                }
                let index = result.threads.entry(thread).or_default();
                let bank = banks.entry(thread).or_default();
                if bank.epoch != epoch {
                    bank.values.clear();
                    bank.epoch = epoch;
                }
                for (k, v) in registers {
                    bank.values.insert(k, v);
                }
                if bank.values.len() > 64 {
                    return Err(err("at most64 register names/thread"));
                }
                bank.sequence = sequence;
                bank.ip = result.records[i].sample_ip;
                index.positions.push(i);
                if index.positions.len() % 128 == 0 {
                    index.checkpoints.push(bank.clone());
                }
            }
        }
        Ok(result)
    }
    pub fn info(&self) -> Value {
        json!({"mode":"replay","sourceMode":self.mode,"events":self.records.len(),"bytes":self.bytes,"threads":self.threads.keys().collect::<Vec<_>>(),"dropped":self.dropped,"memoryAvailable":false,"completeExecution":false})
    }
    pub fn events(&self, offset: usize, limit: usize, thread: Option<u32>) -> Result<Value> {
        if !(1..=512).contains(&limit) || offset > self.records.len() {
            return Err(err("invalid replay page;limit1..512"));
        }
        let events = self
            .records
            .iter()
            .enumerate()
            .skip(offset)
            .filter(|(_, r)| thread.map_or(true, |t| r.thread == t))
            .take(limit)
            .map(|(i, r)| json!({"index":i,"event":r.raw}))
            .collect::<Vec<_>>();
        Ok(
            json!({"mode":"replay","sourceMode":self.mode,"events":events,"total":self.records.len(),"memoryAvailable":false}),
        )
    }
    pub fn state(&self, index: usize, thread: Option<u32>) -> Result<Value> {
        let selected = self
            .records
            .get(index)
            .ok_or_else(|| err("replay index outside trace"))?;
        let tid = thread.unwrap_or(selected.thread);
        let mut point = RegisterPoint::default();
        if let Some(t) = self.threads.get(&tid) {
            let count = t.positions.partition_point(|&i| i <= index);
            let completed = count / 128;
            if completed > 0 {
                point = t.checkpoints[completed - 1].clone();
            }
            for &i in &t.positions[completed * 128..count] {
                let r = &self.records[i];
                if point.epoch != r.epoch {
                    point.values.clear();
                    point.epoch = r.epoch;
                }
                for (k, v) in &r.registers {
                    point.values.insert(k.clone(), *v);
                }
                point.sequence = r.sequence;
                point.ip = r.sample_ip;
            }
        }
        let continuous = point.epoch == selected.epoch;
        Ok(
            json!({"mode":"replay","sourceMode":self.mode,"index":index,"sequence":selected.sequence,"thread":tid,"capturedAtSequence":if point.sequence==0{None}else{Some(point.sequence)},"stateCapturedAtSelectedEvent":continuous&&point.sequence==selected.sequence,"instructionPointer":point.ip.map(Address),"selectedEventAddress":selected.address.map(Address),"sampleTiming":if self.mode=="emulated"{"after emulated instruction"}else{"observed paused instruction boundary"},"registers":point.values.into_iter().map(|(k,v)|(k,v.map(Address))).collect::<BTreeMap<_,_>>(),"registersComplete":false,"memoryAvailable":false,"discontinuous":!continuous,"missingState":"Registers not captured remain unavailable; values are as of capturedAtSequence. Historical memory was not captured."}),
        )
    }
    pub fn overlay(
        &self,
        analysis: &crate::ProgramAnalysis,
        image_sha: &str,
        static_base: u64,
    ) -> Result<Value> {
        if !sha(image_sha) {
            return Err(err("expected original image SHA256 required"));
        }
        let mut samples: BTreeMap<Address, u64> = BTreeMap::new();
        let mut entries: BTreeMap<Address, u64> = BTreeMap::new();
        let mut transitions = vec![];
        let mut transition_count = 0u64;
        let mut previous: BTreeMap<u32, (&Record, u64)> = BTreeMap::new();
        let mut unknown = 0;
        for r in &self.records {
            if r.kind != "instruction" {
                continue;
            }
            let mapped = r
                .module
                .as_ref()
                .filter(|m| {
                    m.sha.as_deref() == Some(&image_sha.to_ascii_lowercase())
                        && r.address == m.base.checked_add(m.rva)
                        && m.rva < m.size
                })
                .and_then(|m| static_base.checked_add(m.rva));
            let Some(address) = mapped else {
                previous.remove(&r.thread);
                unknown += 1;
                continue;
            };
            if let Some(block) = analysis.block_containing(address) {
                *samples.entry(Address(block.address)).or_default() += 1;
                if address == block.address {
                    *entries.entry(Address(block.address)).or_default() += 1;
                }
            }
            if let Some((last, from)) = previous.get(&r.thread) {
                if last.epoch == r.epoch {
                    if let Some(i) = analysis.instructions.get(from) {
                        if !matches!(i.flow, crate::InstructionFlow::Next) {
                            transition_count += 1;
                            if transitions.len() >= 512 {
                                previous.insert(r.thread, (r, address));
                                continue;
                            }
                            let exists = analysis
                                .block_containing(*from)
                                .is_some_and(|b| b.successors.iter().any(|e| e.target == address))
                                || i.target == Some(address);
                            transitions.push(json!({"thread":r.thread,"fromSequence":last.sequence,"toSequence":r.sequence,"sourceRuntime":last.address.map(Address),"destinationRuntime":r.address.map(Address),"sourceStatic":Address(*from),"destinationStatic":Address(address),"kind":format!("{:?}",i.flow),"sourceBlock":analysis.block_containing(*from).map(|b|Address(b.address)),"destinationBlock":analysis.block_containing(address).map(|b|Address(b.address)),"existsInStatic":exists,"uncertainty":"Consecutive captured IP samples; static classification assumes matching image bytes at source. No CFG mutation."}));
                        }
                    }
                }
            }
            previous.insert(r.thread, (r, address));
        }
        Ok(
            json!({"mode":"observedEvidenceOverlay","sourceMode":self.mode,"imageSha256":image_sha,"blockInstructionObservations":samples,"blockEntryObservations":entries,"transitionCount":transition_count,"retainedTransitions":transitions.len(),"transitionsTruncated":transition_count>transitions.len() as u64,"transitions":transitions,"unmappedInstructionObservations":unknown,"completeCoverage":false,"mutatesStaticCfg":false}),
        )
    }
}
