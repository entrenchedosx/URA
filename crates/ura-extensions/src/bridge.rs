use crate::{bounded, invalid, Result};
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use std::{
    collections::BTreeSet,
    io::Write,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
use ura_service::{FunctionSort, Service, XrefDirection};

pub(crate) struct Bridge {
    pub service: Arc<Mutex<Service>>,
    pub handle: String,
    pub identity: String,
    pub grants: BTreeSet<String>,
    pub deadline: Option<Instant>,
    pub shutdown: Arc<AtomicBool>,
    pub origin: Option<String>,
    pub cancel: Arc<AtomicBool>,
    pub findings: Vec<Value>,
    pub symbolic: BTreeSet<String>,
    pub emulation: BTreeSet<String>,
}
impl Bridge {
    pub fn new(
        service: Arc<Mutex<Service>>,
        handle: String,
        grants: BTreeSet<String>,
        origin: Option<String>,
        cancel: Arc<AtomicBool>,
    ) -> Result<Self> {
        let identity = if handle.is_empty() {
            "detached-event-or-format-callback".into()
        } else {
            service
                .try_lock()
                .map_err(|_| "Analysis service busy; retry")?
                .extension_identity(&handle)
                .map_err(|e| e.to_string())?
        };
        Ok(Self {
            service,
            handle,
            identity,
            grants,
            origin,
            deadline: None,
            shutdown: cancel.clone(),
            cancel,
            findings: Vec::new(),
            symbolic: BTreeSet::new(),
            emulation: BTreeSet::new(),
        })
    }
    fn grant(&self, cap: &str) -> Result<()> {
        if self.grants.contains(cap) {
            Ok(())
        } else {
            invalid(format!("Permission denied: {cap}"))
        }
    }
    pub fn call(&mut self, method: &str, mut p: Value) -> Result<Value> {
        if self.cancel.load(Ordering::Acquire) {
            return invalid("Script cancelled");
        }
        let cap = match method {
            "__validate" => "",
            "metadata" | "bytes" | "mapping" | "symbols" => "project.read",
            "functions" | "function" | "instructions" | "cfg" | "ir" | "dataflow"
            | "pseudocode" | "signature" | "stack" | "types" | "xrefs" | "typeLibrary"
            | "finding" => "analysis.read",
            "transaction" => "project.write",
            "symbolic" => "analysis.symbolic",
            "emulation" => "emulation.execute",
            "debugger" => "debugger.read",
            "export" => "files.export",
            "cancelled" => return Ok(json!(false)),
            _ => return invalid("Unsupported SDK host method"),
        };
        if method != "__validate" {
            self.grant(cap)?;
        }
        if self.handle.is_empty() {
            return invalid("Detached callback has no live static project");
        }
        let mut service = loop {
            if self.cancel.load(Ordering::Acquire)
                || self.shutdown.load(Ordering::Acquire)
                || self.deadline.is_some_and(|d| Instant::now() >= d)
            {
                return invalid("Script cancelled/deadline exceeded waiting for analysis service");
            }
            match self.service.try_lock() {
                Ok(s) => break s,
                Err(std::sync::TryLockError::Poisoned(e)) => break e.into_inner(),
                Err(_) => std::thread::sleep(Duration::from_millis(5)),
            }
        };
        if service
            .extension_identity(&self.handle)
            .map_err(|e| e.to_string())?
            != self.identity
        {
            return invalid("Stale project/analysis identity; restart the interpreter session");
        }
        let address = p["address"].as_str().unwrap_or("0x0").to_string();
        let offset = number(&p, "offset", 0, usize::MAX)?;
        let limit = number(&p, "limit", 128, 2000)?;
        let value = match method {
            "__validate" => json!(true),
            "metadata" => result(service.extension_metadata(&self.handle))?,
            "mapping" => result(service.extension_mapping(&self.handle, &address))?,
            "symbols" => result(service.extension_symbols(&self.handle, offset, limit.min(256)))?,
            "functions" => result(service.functions(
                &self.handle,
                None,
                offset,
                limit.min(1000),
                FunctionSort::Address,
            ))?,
            "function" => result(service.function(&self.handle, &address, limit.min(500)))?,
            "instructions" => result(service.disassembly(&self.handle, &address, limit))?,
            "cfg" => result(service.cfg(&self.handle, &address, limit.min(500)))?,
            "ir" => result(service.ir(
                &self.handle,
                &address,
                p["ssa"].as_bool().unwrap_or(false),
                offset,
                limit.min(500),
            ))?,
            "dataflow" => result(service.analysis_diagnostics(
                &self.handle,
                &address,
                offset,
                limit.min(500),
            ))?,
            "pseudocode" => {
                result(service.decompile(&self.handle, &address, offset, limit, false))?
            }
            "signature" => result(service.function_signature(&self.handle, &address))?,
            "stack" => result(service.stack_frame(&self.handle, &address))?,
            "types" => result(service.inferred_types(&self.handle, &address))?,
            "typeLibrary" => result(service.type_library(&self.handle))?,
            "xrefs" => {
                let direction = match p["direction"].as_str().unwrap_or("outgoing") {
                    "incoming" => XrefDirection::To,
                    "outgoing" => XrefDirection::From,
                    _ => return invalid("Invalid xref direction"),
                };
                result(service.xrefs(&self.handle, &address, direction, None, limit))?
            }
            "bytes" => {
                let space = p["space"].as_str().unwrap_or("effective");
                if !["effective", "original"].contains(&space) {
                    return invalid("SDK static bytes require original/effective; live/emulated bytes have separate APIs");
                }
                result(service.extension_bytes(
                    &self.handle,
                    &address,
                    number(&p, "length", 16, 8192)?,
                    space == "original",
                ))?
            }
            "transaction" => {
                let edits: Vec<ura_project::scripting::MetadataEdit> =
                    serde_json::from_value(p["edits"].clone())
                        .map_err(|e| format!("Invalid transaction: {e}"))?;
                service.extension_origin(self.origin.clone());
                let result = service.extension_transaction(&self.handle, &self.identity, &edits);
                service.extension_origin(None);
                let value = result.map_err(|e| e.to_string())?;
                self.identity = service
                    .extension_identity(&self.handle)
                    .map_err(|e| e.to_string())?;
                value
            }
            "symbolic" => {
                let action = required(&p, "action")?.to_string();
                if action == "start" {
                    p["handle"] = json!(self.handle);
                } else if !self.symbolic.contains(required(&p, "session")?) {
                    return invalid("Symbolic session is not owned by this interpreter");
                }
                if ![
                    "start", "status", "summary", "page", "proof", "model", "cancel", "close",
                ]
                .contains(&action.as_str())
                {
                    return invalid("Symbolic SDK action unsupported");
                }
                let value = service.symbolic_rpc(p).map_err(|e| e.to_string())?;
                if action == "start" {
                    self.symbolic.insert(required(&value, "session")?.into());
                }
                value
            }
            "emulation" => {
                let action = required(&p, "action")?.to_string();
                if action != "create" && !self.emulation.contains(required(&p, "session")?) {
                    return invalid("Emulation session is not owned by this interpreter");
                }
                if ![
                    "create", "status", "step", "run", "stop", "memory", "trace", "close",
                ]
                .contains(&action.as_str())
                {
                    return invalid("Emulation SDK action unsupported");
                }
                if action == "create" && p.get("path").is_some() {
                    return invalid("SDK emulation creation requires explicit virtual config");
                }
                p["operation"] = json!("emulation");
                let value = service.dynamic_rpc(p).map_err(|e| e.to_string())?;
                if action == "create" {
                    self.emulation.insert(required(&value, "session")?.into());
                }
                value
            }
            "debugger" => {
                let action = required(&p, "action")?.to_string();
                if ![
                    "status",
                    "registers",
                    "threads",
                    "breakpoints",
                    "pause",
                    "continue",
                    "stepInto",
                    "stepOver",
                    "stepOut",
                ]
                .contains(&action.as_str())
                {
                    return invalid("Debugger SDK exposes existing-session inspection/step controls only; launch/attach/live memory/write unavailable");
                }
                if ["pause", "continue", "stepInto", "stepOver", "stepOut"]
                    .contains(&action.as_str())
                {
                    self.grant("debugger.control")?;
                }
                p.as_object_mut().unwrap().remove("action");
                if action == "stepInto" || action == "stepOver" {
                    p["operation"] = json!("step");
                    p["over"] = json!(action == "stepOver");
                } else {
                    p["operation"] = json!(action);
                }
                service.debugger.rpc(p).map_err(|e| e.to_string())?
            }
            "export" => {
                if !service.extension_writes_enabled() {
                    return invalid("Host write permission is disabled");
                }
                let path = service
                    .extension_policy()
                    .allow_write(Path::new(required(&p, "destination")?))
                    .map_err(|e| e.to_string())?;
                let bytes = serde_json::to_vec_pretty(&p["data"]).map_err(|e| e.to_string())?;
                if bytes.len() > 512 * 1024 {
                    return invalid("Export exceeds512KiB");
                }
                let mut file = std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&path)
                    .map_err(|e| e.to_string())?;
                file.write_all(&bytes).map_err(|e| e.to_string())?;
                json!({"path":path,"bytes":bytes.len(),"sha256":ura_core::sha256_hex(&bytes)})
            }
            "finding" => {
                if serde_json::to_vec(&self.findings)
                    .map_err(|e| e.to_string())?
                    .len()
                    + serde_json::to_vec(&p).map_err(|e| e.to_string())?.len()
                    > 131072
                    || self.findings.len() >= 128
                    || serde_json::to_vec(&p).map_err(|e| e.to_string())?.len() > 16384
                {
                    return invalid("Finding count/size limit");
                }
                for key in ["title", "explanation", "category", "severity", "confidence"] {
                    let v = required(&p, key)?;
                    if v.is_empty() || v.len() > 4096 {
                        return invalid("Finding text invalid");
                    }
                }
                if !["candidate", "observed", "unverified"].contains(&required(&p, "confidence")?) {
                    return invalid("Plugin claims cannot be promoted to host-proven facts");
                }
                if !["info", "warning", "error"].contains(&required(&p, "severity")?) {
                    return invalid("Finding severity invalid");
                }
                ura_core::parse_address(&address).map_err(|e| e.to_string())?;
                p["sourcePlugin"] = json!(self.origin);
                p["projectIdentity"] = json!(self.identity);
                p["authority"] = json!("plugin-generated claim; not a host proof");
                self.findings.push(p);
                json!({"accepted":true})
            }
            _ => return invalid("Unsupported method"),
        };
        bounded(value)
    }
}
impl Drop for Bridge {
    fn drop(&mut self) {
        if self.symbolic.is_empty() && self.emulation.is_empty() {
            return;
        }
        let service = self.service.clone();
        let symbolic = std::mem::take(&mut self.symbolic);
        let emulation = std::mem::take(&mut self.emulation);
        // A host call already holding the service lock finishes independently. The
        // controller never joins cleanup while waiting for that lock.
        let _ = std::thread::Builder::new()
            .name("ura-sdk-cleanup".into())
            .spawn(move || {
                let mut service = service.lock().unwrap_or_else(|e| e.into_inner());
                for session in symbolic {
                    let _ = service.symbolic_rpc(json!({"action":"cancel","session":session}));
                    let _ = service.symbolic_rpc(json!({"action":"close","session":session}));
                }
                for session in emulation {
                    let _ = service.dynamic_rpc(
                        json!({"operation":"emulation","action":"close","session":session}),
                    );
                }
            });
    }
}
pub(crate) fn required<'a>(p: &'a Value, key: &str) -> Result<&'a str> {
    p[key]
        .as_str()
        .ok_or_else(|| format!("{key} string required"))
}
pub(crate) fn number(p: &Value, key: &str, default: usize, max: usize) -> Result<usize> {
    let n = match p.get(key) {
        None => default,
        Some(v) => usize::try_from(v.as_u64().ok_or("Unsigned integer required")?)
            .map_err(|e| e.to_string())?,
    };
    if n > max {
        invalid(format!("{key} limit exceeded"))
    } else {
        Ok(n)
    }
}
fn result<T: serde::Serialize>(
    value: std::result::Result<T, ura_service::ServiceError>,
) -> Result<Value> {
    serde_json::to_value(value.map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}
