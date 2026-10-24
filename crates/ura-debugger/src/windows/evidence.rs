//! Immutable captured runtime bytes, separate from file patches and live memory.
use super::*;
use windows_sys::Win32::System::Memory::*;
#[derive(Default)]
pub(super) struct Captures {
    next: u64,
    bytes: usize,
    values: BTreeMap<u64, Value>,
}
fn query(process: HANDLE, address: u64) -> Result<MEMORY_BASIC_INFORMATION> {
    let mut region = MEMORY_BASIC_INFORMATION::default();
    unsafe {
        if VirtualQueryEx(
            process,
            address as *const _,
            &mut region,
            std::mem::size_of_val(&region),
        ) == 0
        {
            return Err(error("VirtualQueryEx"));
        }
    }
    Ok(region)
}
fn readable(region: &MEMORY_BASIC_INFORMATION) -> bool {
    region.State == MEM_COMMIT
        && region.Protect & (PAGE_GUARD | PAGE_NOACCESS) == 0
        && region.Protect
            & (PAGE_READONLY
                | PAGE_READWRITE
                | PAGE_WRITECOPY
                | PAGE_EXECUTE_READ
                | PAGE_EXECUTE_READWRITE
                | PAGE_EXECUTE_WRITECOPY)
            != 0
}
fn region_value(r: &MEMORY_BASIC_INFORMATION) -> Value {
    json!({"base":hex(r.BaseAddress as u64),"allocationBase":hex(r.AllocationBase as u64),"size":r.RegionSize,"protection":r.Protect,"state":r.State,"type":r.Type,"readable":readable(r)})
}
pub(super) fn regions(process: HANDLE, address: u64, limit: usize) -> Result<Value> {
    if limit == 0 || limit > 256 {
        return Err(DebugError::new("limit", "region page limit1..256"));
    }
    let mut cursor = address;
    let mut values = Vec::new();
    let mut failure = None;
    for _ in 0..limit {
        match query(process, cursor) {
            Ok(r) => {
                let end = (r.BaseAddress as u64)
                    .checked_add(r.RegionSize as u64)
                    .filter(|&n| n > cursor);
                values.push(region_value(&r));
                if let Some(next) = end {
                    cursor = next;
                } else {
                    failure = Some("region traversal reached address boundary".to_string());
                    break;
                }
            }
            Err(e) => {
                failure = Some(e.message);
                break;
            }
        }
    }
    Ok(
        json!({"addressSpace":"runtime","regions":values,"nextAddress":if failure.is_none(){Some(hex(cursor))}else{None},"endReason":failure}),
    )
}
impl WindowsBackend {
    fn capture_range(&self, address: u64, length: usize) -> Result<Value> {
        self.paused()?;
        if length == 0 || length > 1024 * 1024 || address.checked_add(length as u64).is_none() {
            return Err(DebugError::new(
                "limit",
                "snapshot range1..1048576 bytes without overflow",
            ));
        }
        let end = address + length as u64;
        let mut cursor = address;
        let mut chunks = Vec::new();
        let mut observed = Vec::new();
        let mut captured = 0;
        let deadline = Instant::now() + std::time::Duration::from_secs(2);
        while cursor < end {
            if chunks.len() >= 256 || Instant::now() >= deadline {
                chunks.push(json!({"address":hex(cursor),"requested":end-cursor,"bytes":[],"missing":end-cursor,"error":"capture traversal/time limit"}));
                break;
            }
            let region = match query(self.process()?, cursor) {
                Ok(region) => region,
                Err(e) => {
                    chunks.push(json!({"address":hex(cursor),"requested":end-cursor,"bytes":[],"missing":end-cursor,"error":e.message}));
                    break;
                }
            };
            let next = (region.BaseAddress as u64)
                .checked_add(region.RegionSize as u64)
                .filter(|v| *v > cursor)
                .ok_or_else(|| DebugError::new("memory", "non-progressing region"))?
                .min(end);
            let size = (next - cursor).min(MAX_MEMORY as u64) as usize;
            let read = if readable(&region) {
                memory(self.process()?, cursor, size)?
            } else {
                json!({"bytes":[],"error":"region is not readable; guard/no-access pages are not touched"})
            };
            let bytes = read["bytes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|b| b.as_u64().unwrap() as u8)
                .collect::<Vec<_>>();
            observed.extend_from_slice(&bytes);
            captured += bytes.len();
            chunks.push(json!({"address":hex(cursor),"requested":size,"bytes":bytes,"missing":size-bytes.len(),"error":read["error"],"region":region_value(&region)}));
            cursor += size as u64;
        }
        let modules = self
            .view
            .modules
            .iter()
            .filter(|m| {
                ura_core::parse_address(&m.base)
                    .is_ok_and(|b| b < end && b.saturating_add(m.size) > address)
            })
            .cloned()
            .collect::<Vec<_>>();
        Ok(
            json!({"schemaVersion":1,"format":"ura-memory-snapshot","addressSpace":"capturedRuntime","session":self.view.session,"pid":self.view.pid,"captureEventSequence":self.view.events.last().map(|e|e.sequence),"elapsedMicros":self.started.elapsed().as_micros() as u64,"address":hex(address),"requested":length,"captured":captured,"missing":length-captured,"complete":captured==length,"capturedBytesSha256":ura_core::sha256_hex(&observed),"hashScope":"concatenated captured bytes in ascending address order; missing bytes excluded","modules":modules,"chunks":chunks,"executableReconstruction":false}),
        )
    }
    pub(super) fn capture_action(&mut self, action: CaptureAction) -> Result<Value> {
        match action {
            CaptureAction::Capture { address, length } => {
                if length == 0
                    || length > 1024 * 1024
                    || address.checked_add(length as u64).is_none()
                {
                    return Err(DebugError::new(
                        "limit",
                        "snapshot range1..1048576 bytes without overflow",
                    ));
                }
                if self.captures.values.len() >= 4
                    || self
                        .captures
                        .bytes
                        .checked_add(length)
                        .is_none_or(|size| size > 4 * 1024 * 1024)
                {
                    return Err(DebugError::new("limit","retain at most4 snapshots and4MiB requested bytes; remove an earlier capture first"));
                }
                let mut value = self.capture_range(address, length)?;
                self.captures.next += 1;
                let id = self.captures.next;
                value["id"] = json!(id);
                self.captures.bytes += length;
                self.captures.values.insert(id, value.clone());
                Ok(value)
            }
            CaptureAction::List => Ok(
                json!({"snapshots":self.captures.values.values().map(|v|json!({"id":v["id"],"address":v["address"],"requested":v["requested"],"captured":v["captured"],"missing":v["missing"],"sha256":v["capturedBytesSha256"]})).collect::<Vec<_>>(),"retainedRequestedBytes":self.captures.bytes}),
            ),
            CaptureAction::Info { id } | CaptureAction::Export { id } => self
                .captures
                .values
                .get(&id)
                .cloned()
                .ok_or_else(|| DebugError::new("snapshot", "unknown snapshot ID")),
            CaptureAction::Remove { id } => {
                let value = self
                    .captures
                    .values
                    .remove(&id)
                    .ok_or_else(|| DebugError::new("snapshot", "unknown snapshot ID"))?;
                self.captures.bytes -= value["requested"].as_u64().unwrap() as usize;
                Ok(json!({"removed":id}))
            }
            CaptureAction::Compare { id, other } => {
                let first = self
                    .captures
                    .values
                    .get(&id)
                    .ok_or_else(|| DebugError::new("snapshot", "unknown snapshot ID"))?
                    .clone();
                let second = if let Some(other) = other {
                    self.captures
                        .values
                        .get(&other)
                        .ok_or_else(|| DebugError::new("snapshot", "unknown comparison snapshot"))?
                        .clone()
                } else {
                    self.capture_range(
                        ura_core::parse_address(first["address"].as_str().unwrap()).unwrap(),
                        first["requested"].as_u64().unwrap() as usize,
                    )?
                };
                compare(&first, &second)
            }
            CaptureAction::Disassembly { id, address, count } => {
                if count == 0 || count > 128 {
                    return Err(DebugError::new("limit", "captured disassembly count1..128"));
                }
                let capture = self
                    .captures
                    .values
                    .get(&id)
                    .ok_or_else(|| DebugError::new("snapshot", "unknown snapshot ID"))?;
                for chunk in capture["chunks"].as_array().unwrap() {
                    let base = ura_core::parse_address(chunk["address"].as_str().unwrap()).unwrap();
                    let bytes = chunk["bytes"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|b| b.as_u64().unwrap() as u8)
                        .collect::<Vec<_>>();
                    if let Some(offset) = address
                        .checked_sub(base)
                        .filter(|off| *off < (bytes.len() as u64))
                    {
                        use ura_core::disasm::InstructionDecoder;
                        let page = ura_core::disasm::X86Decoder
                            .decode(&bytes[offset as usize..], address, 64, None, count)
                            .map_err(|e| DebugError::new("decode", e.to_string()))?;
                        return Ok(
                            json!({"addressSpace":"capturedRuntime","snapshot":id,"instructions":page.instructions,"note":"decodes one captured contiguous chunk; gaps are not filled"}),
                        );
                    }
                }
                Err(DebugError::new(
                    "memory",
                    "address is not within captured bytes",
                ))
            }
        }
    }
}
fn flatten(snapshot: &Value) -> Vec<Option<u8>> {
    let base = ura_core::parse_address(snapshot["address"].as_str().unwrap()).unwrap();
    let mut result = vec![None; snapshot["requested"].as_u64().unwrap() as usize];
    for chunk in snapshot["chunks"].as_array().unwrap() {
        let off =
            (ura_core::parse_address(chunk["address"].as_str().unwrap()).unwrap() - base) as usize;
        for (i, b) in chunk["bytes"].as_array().unwrap().iter().enumerate() {
            result[off + i] = Some(b.as_u64().unwrap() as u8);
        }
    }
    result
}
fn compare(a: &Value, b: &Value) -> Result<Value> {
    if a["address"] != b["address"] || a["requested"] != b["requested"] {
        return Err(DebugError::new(
            "snapshot",
            "comparison requires the same runtime address and requested length",
        ));
    }
    let base = ura_core::parse_address(a["address"].as_str().unwrap()).unwrap();
    let first = flatten(a);
    let second = flatten(b);
    let mut differences = Vec::new();
    let mut changed = 0;
    let mut unknown = 0;
    for (i, (a, b)) in first.iter().zip(second.iter()).enumerate() {
        match (a, b) {
            (Some(a), Some(b)) if a != b => {
                changed += 1;
                if differences.len() < 256 {
                    differences.push(json!({"address":hex(base+i as u64),"before":a,"after":b}));
                }
            }
            (None, _) | (_, None) => unknown += 1,
            _ => {}
        }
    }
    Ok(
        json!({"addressSpace":"capturedRuntime","changedBytes":changed,"unknownBytes":unknown,"differences":differences,"differencesTruncated":changed>256,"equalObservedBytes":changed==0,"completeComparison":unknown==0}),
    )
}
