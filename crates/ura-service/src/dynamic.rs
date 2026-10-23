//! Shared isolated execution/evidence service; no live debugger permissions flow here.
use crate::{PathPolicy, ServiceError};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::JoinHandle,
};
use ura_core::{
    dynamic::{
        self,
        cpu::{Config, Emulator},
        image::{Image, Segment},
        replay::Replay,
    },
    ir::Address,
};
type Result<T> = std::result::Result<T, ServiceError>;
fn invalid(s: impl Into<String>) -> ServiceError {
    ServiceError::InvalidArgument(s.into())
}
fn engine<T>(r: dynamic::Result<T>) -> Result<T> {
    r.map_err(|e| invalid(e.to_string()))
}
fn address(v: Option<String>, name: &str) -> Result<u64> {
    ura_core::parse_address(&v.ok_or_else(|| invalid(format!("{name} required")))?)
        .map_err(ServiceError::from)
}
fn default_steps() -> u64 {
    1000
}
fn default_limit() -> usize {
    128
}
fn default_bits() -> u8 {
    64
}
#[derive(Deserialize)]
#[serde(
    tag = "operation",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum Request {
    Emulation {
        action: String,
        session: Option<String>,
        config: Option<Box<Config>>,
        path: Option<PathBuf>,
        image: Option<String>,
        entry: Option<String>,
        base: Option<String>,
        #[serde(default)]
        raw: bool,
        #[serde(default = "default_bits")]
        bitness: u8,
        #[serde(default = "default_steps")]
        steps: u64,
        until: Option<String>,
        address: Option<String>,
        length: Option<usize>,
        #[serde(default)]
        after: u64,
        #[serde(default = "default_limit")]
        limit: usize,
        id: Option<u64>,
        enabled: Option<bool>,
        destination: Option<PathBuf>,
    },
    Replay {
        action: String,
        handle: Option<String>,
        path: Option<PathBuf>,
        #[serde(default)]
        index: usize,
        #[serde(default)]
        offset: usize,
        #[serde(default = "default_limit")]
        limit: usize,
        thread: Option<u32>,
    },
    Image {
        action: String,
        bitness: Option<u8>,
        handle: Option<String>,
        path: Option<PathBuf>,
        entry: Option<String>,
        address: Option<String>,
        length: Option<usize>,
        other: Option<String>,
        destination: Option<PathBuf>,
    },
}
struct Entry {
    cpu: Arc<Mutex<Emulator>>,
    view: Arc<Mutex<Value>>,
    cancel: Arc<AtomicBool>,
    busy: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}
impl Entry {
    fn locked(&self) -> Result<std::sync::MutexGuard<'_, Emulator>> {
        if self.busy.load(Ordering::Acquire) {
            return Err(invalid(
                "emulation is running; stop and poll status before editing/inspection",
            ));
        }
        self.cpu
            .try_lock()
            .map_err(|_| invalid("emulation worker busy"))
    }
    fn state(&self) -> Value {
        json!({"busy":self.busy.load(Ordering::Acquire),"state":self.view.lock().unwrap_or_else(|e|e.into_inner()).clone()})
    }
    fn refresh(&self, state: Value) {
        *self.view.lock().unwrap_or_else(|e| e.into_inner()) = state;
    }
    fn run(&mut self, count: u64, until: Option<u64>) -> Result<Value> {
        if count == 0 || count > 1000000 {
            return Err(invalid("run steps1..1000000"));
        }
        if self.busy.swap(true, Ordering::AcqRel) {
            return Err(invalid("emulation already running"));
        }
        if let Some(old) = self.worker.take() {
            let _ = old.join();
        }
        self.cancel.store(false, Ordering::Release);
        let cpu = self.cpu.clone();
        let view = self.view.clone();
        let cancel = self.cancel.clone();
        let busy = self.busy.clone();
        self.worker = Some(std::thread::spawn(move || {
            let mut cpu = cpu.lock().unwrap_or_else(|e| e.into_inner());
            cpu.run(count, until, &cancel, |state| {
                *view.lock().unwrap_or_else(|e| e.into_inner()) = json!(state);
            });
            *view.lock().unwrap_or_else(|e| e.into_inner()) = json!(cpu.state());
            busy.store(false, Ordering::Release);
        }));
        Ok(self.state())
    }
}
impl Drop for Entry {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}
pub struct DynamicService {
    policy: PathPolicy,
    writes: bool,
    emulation_enabled: bool,
    next: u64,
    emulators: BTreeMap<String, Entry>,
    replays: BTreeMap<String, Replay>,
    images: BTreeMap<String, Image>,
}
impl DynamicService {
    pub fn new(policy: PathPolicy, writes: bool) -> Self {
        Self {
            policy,
            writes,
            emulation_enabled: false,
            next: 1,
            emulators: BTreeMap::new(),
            replays: BTreeMap::new(),
            images: BTreeMap::new(),
        }
    }
    pub fn with_emulation(mut self, enabled: bool) -> Self {
        self.emulation_enabled = enabled;
        self
    }
    fn next(&mut self, prefix: &str) -> String {
        let n = self.next;
        self.next += 1;
        format!("{prefix}-{n}")
    }
    fn read(&self, path: &Path) -> Result<Vec<u8>> {
        let p = self.policy.allow_read(path)?;
        let f = std::fs::File::open(p).map_err(|e| ServiceError::Io(e.to_string()))?;
        if f.metadata()
            .map_err(|e| ServiceError::Io(e.to_string()))?
            .len()
            > 16 * 1024 * 1024
        {
            return Err(invalid("dynamic input exceeds16MiB"));
        }
        let mut data = vec![];
        f.take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut data)
            .map_err(|e| ServiceError::Io(e.to_string()))?;
        if data.len() > 16 * 1024 * 1024 {
            return Err(invalid("dynamic input exceeds16MiB"));
        }
        Ok(data)
    }
    fn export(&self, value: &Value, path: &Path) -> Result<Value> {
        if !self.writes {
            return Err(ServiceError::WriteDisabled);
        }
        let p = self.policy.allow_write(path)?;
        if p.exists() {
            return Err(invalid("dynamic export never overwrites existing files"));
        }
        let bytes = serde_json::to_vec_pretty(value).map_err(|e| invalid(e.to_string()))?;
        if bytes.len() > 16 * 1024 * 1024 {
            return Err(invalid("dynamic export exceeds16MiB"));
        }
        let mut file = tempfile::NamedTempFile::new_in(
            p.parent()
                .ok_or_else(|| invalid("destination parent required"))?,
        )
        .map_err(|e| ServiceError::Io(e.to_string()))?;
        file.write_all(&bytes)
            .and_then(|_| file.as_file().sync_all())
            .map_err(|e| ServiceError::Io(e.to_string()))?;
        file.persist_noclobber(&p)
            .map_err(|e| ServiceError::Io(e.to_string()))?;
        Ok(
            json!({"destination":p,"bytes":bytes.len(),"sha256":ura_core::sha256_hex(&bytes),"format":value["format"]}),
        )
    }
    pub fn rpc(&mut self, value: Value) -> Result<Value> {
        let req: Request = serde_json::from_value(value).map_err(|e| invalid(e.to_string()))?;
        let result = self.execute(req)?;
        if serde_json::to_vec(&result)
            .map_err(|e| invalid(e.to_string()))?
            .len()
            > 8 * 1024 * 1024
        {
            return Err(invalid(
                "dynamic reply exceeds8MiB; use smaller pages/ranges",
            ));
        }
        Ok(result)
    }
    pub fn insert_image(&mut self, image: Image) -> Result<Value> {
        if self.images.len() >= 4 {
            return Err(invalid("at most4 memory images"));
        }
        engine(image.validate())?;
        let id = self.next("image");
        self.images.insert(id.clone(), image);
        Ok(json!({"handle":id}))
    }
    pub fn overlay(
        &self,
        handle: &str,
        analysis: &ura_core::ProgramAnalysis,
        sha: &str,
        base: u64,
    ) -> Result<Value> {
        engine(
            self.replays
                .get(handle)
                .ok_or_else(|| invalid("unknown replay handle"))?
                .overlay(analysis, sha, base),
        )
    }
    fn execute(&mut self, req: Request) -> Result<Value> {
        match req {
            Request::Emulation {
                action,
                session,
                config,
                path,
                image,
                entry,
                base,
                raw,
                bitness,
                steps,
                until,
                address: a,
                length,
                after,
                limit,
                id,
                enabled,
                destination,
            } => {
                if !self.emulation_enabled {
                    return Err(invalid("isolated emulation requires separate --enable-emulation; it grants no native launch/attach, capture or file writes"));
                }
                if action == "create" {
                    if self.emulators.len() >= 4 {
                        return Err(invalid("at most4 emulation sessions; close one first"));
                    }
                    if path.is_some() && image.is_some() {
                        return Err(invalid("choose one image source"));
                    }
                    let mut cfg = config.map(|c| *c).unwrap_or_default();
                    if let Some(path) = path {
                        if !raw && base.is_some() {
                            return Err(invalid("rebasing a native executable is unsupported; use its preferred addresses"));
                        }
                        let data = self.read(&path)?;
                        let binary = if raw {
                            ura_core::binary::analyze_raw_bytes(
                                &path,
                                data,
                                Some(match base {
                                    Some(v) => ura_core::parse_address(&v)?,
                                    None => 0x1000,
                                }),
                                u32::from(bitness),
                            )?
                        } else {
                            ura_core::binary::analyze_bytes(&path, data)?
                        };
                        let selected = match entry {
                            Some(v) => ura_core::parse_address(&v)?,
                            None => binary
                                .analysis()
                                .entry_point
                                .ok_or_else(|| invalid("explicit entry required"))?,
                        };
                        cfg = engine(Image::from_binary(&binary))?
                            .config(selected, cfg)
                            .map_err(|e| invalid(e.to_string()))?;
                    } else if let Some(handle) = image {
                        let image = self
                            .images
                            .get(&handle)
                            .ok_or_else(|| invalid("unknown memory-image handle"))?;
                        cfg = engine(image.config(address(entry, "entry")?, cfg))?;
                    } else if let Some(entry) = entry {
                        cfg.entry = Address(ura_core::parse_address(&entry)?);
                    }
                    let cpu = engine(Emulator::new(cfg))?;
                    let view = json!(cpu.state());
                    let handle = self.next("emu");
                    self.emulators.insert(
                        handle.clone(),
                        Entry {
                            cpu: Arc::new(Mutex::new(cpu)),
                            view: Arc::new(Mutex::new(view.clone())),
                            cancel: Arc::new(AtomicBool::new(false)),
                            busy: Arc::new(AtomicBool::new(false)),
                            worker: None,
                        },
                    );
                    return Ok(json!({"session":handle,"busy":false,"state":view}));
                }
                let handle = session.ok_or_else(|| invalid("emulation session required"))?;
                if action == "close" {
                    self.emulators
                        .remove(&handle)
                        .ok_or_else(|| invalid("unknown emulation session"))?;
                    return Ok(json!({"closed":handle}));
                }
                let e = self
                    .emulators
                    .get_mut(&handle)
                    .ok_or_else(|| invalid("unknown emulation session"))?;
                match action.as_str() {
                    "status" => Ok(e.state()),
                    "stop" => {
                        e.cancel.store(true, Ordering::Release);
                        Ok(e.state())
                    }
                    "run" | "step" => e.run(
                        if action == "step" { 1 } else { steps },
                        until.map(|v| ura_core::parse_address(&v)).transpose()?,
                    ),
                    "reset" | "restore" => {
                        let state = {
                            let mut cpu = e.locked()?;
                            engine(cpu.restore(if action == "reset" { None } else { id }))?;
                            json!(cpu.state())
                        };
                        e.refresh(state);
                        Ok(e.state())
                    }
                    "snapshot" => {
                        let (id, state) = {
                            let mut cpu = e.locked()?;
                            let id = engine(cpu.save())?;
                            (id, json!(cpu.state()))
                        };
                        e.refresh(state);
                        Ok(json!({"id":id}))
                    }
                    "removeSnapshot" => {
                        let state = {
                            let mut cpu = e.locked()?;
                            engine(cpu.remove_snapshot(id.ok_or_else(|| invalid("id required"))?))?;
                            json!(cpu.state())
                        };
                        e.refresh(state);
                        Ok(json!({"removed":id}))
                    }
                    "breakpoint" => {
                        let address = address(a, "address")?;
                        let mut cpu = e.locked()?;
                        if cpu.breakpoints.len() >= 256 && enabled.unwrap_or(true) {
                            return Err(invalid("at most256 emulated breakpoints"));
                        }
                        if enabled.unwrap_or(true) {
                            cpu.breakpoints.insert(address);
                        } else {
                            cpu.breakpoints.remove(&address);
                        }
                        Ok(
                            json!({"breakpoints":cpu.breakpoints.iter().copied().map(Address).collect::<Vec<_>>()}),
                        )
                    }
                    "memory" => {
                        let address = address(a, "address")?;
                        let cpu = e.locked()?;
                        let bytes = engine(cpu.memory.read(address, length.unwrap_or(256)))?;
                        Ok(
                            json!({"mode":"emulated","address":Address(address),"bytes":bytes,"regions":cpu.memory.regions}),
                        )
                    }
                    "disassembly" => {
                        use ura_core::InstructionDecoder;
                        let a = address(a, "address")?;
                        let cpu = e.locked()?;
                        let bytes = engine(cpu.memory.fetch(a))?;
                        let page =
                            ura_core::X86Decoder.decode(&bytes, a, cpu.config.bitness, None, 1)?;
                        Ok(json!({"mode":"emulated","instructions":page.instructions}))
                    }
                    "trace" => engine(e.locked()?.trace(after, limit)),
                    "exportTrace" => {
                        let value = e.locked()?.export_trace();
                        self.export(
                            &value,
                            &destination.ok_or_else(|| invalid("destination required"))?,
                        )
                    }
                    "memoryImage" => {
                        if self.images.len() >= 4 {
                            return Err(invalid("at most4 memory images"));
                        }
                        let image = {
                            let cpu = e.locked()?;
                            Image {
                                format: "ura-memory-image".into(),
                                schema_version: 1,
                                bitness: cpu.config.bitness,
                                provenance:
                                    "Emulated virtual memory; not observed live process memory"
                                        .into(),
                                segments: cpu
                                    .memory
                                    .regions
                                    .iter()
                                    .map(|r| Segment {
                                        base: r.base,
                                        bytes: r.bytes_for_image(),
                                        permissions: r.permissions,
                                    })
                                    .collect(),
                                missing: vec![],
                                original_sha256: None,
                                capture_metadata: Some(
                                    json!({"mode":"emulated","state":cpu.state()}),
                                ),
                            }
                        };
                        let id = self.next("image");
                        self.images.insert(id.clone(), image);
                        Ok(json!({"handle":id,"mode":"emulatedMemoryImage"}))
                    }
                    _ => Err(invalid("unknown emulation action")),
                }
            }
            Request::Replay {
                action,
                handle,
                path,
                index,
                offset,
                limit,
                thread,
            } => {
                if action == "open" {
                    if self.replays.len() >= 4 {
                        return Err(invalid("at most4 replay handles"));
                    }
                    let data = self.read(&path.ok_or_else(|| invalid("path required"))?)?;
                    let replay = engine(Replay::load(&data))?;
                    let info = replay.info();
                    let id = self.next("replay");
                    self.replays.insert(id.clone(), replay);
                    return Ok(json!({"handle":id,"info":info}));
                }
                let handle = handle.ok_or_else(|| invalid("replay handle required"))?;
                if action == "close" {
                    self.replays
                        .remove(&handle)
                        .ok_or_else(|| invalid("unknown replay handle"))?;
                    return Ok(json!({"closed":handle}));
                }
                let replay = self
                    .replays
                    .get(&handle)
                    .ok_or_else(|| invalid("unknown replay handle"))?;
                match action.as_str() {
                    "info" => Ok(replay.info()),
                    "events" => engine(replay.events(offset, limit, thread)),
                    "state" => engine(replay.state(index, thread)),
                    _ => Err(invalid("replay action: open/info/events/state/close")),
                }
            }
            Request::Image {
                action,
                bitness,
                handle,
                path,
                entry,
                address: a,
                length,
                other,
                destination,
            } => {
                if action == "open" || action == "openBinary" {
                    if self.images.len() >= 4 {
                        return Err(invalid("at most4 memory images"));
                    }
                    let path = path.ok_or_else(|| invalid("path required"))?;
                    let data = self.read(&path)?;
                    let mut image = if action == "open" {
                        engine(Image::load(&data))?
                    } else {
                        engine(Image::from_binary(&ura_core::binary::analyze_bytes(
                            &path,
                            data.clone(),
                        )?))?
                    };
                    if let Some(bits) = bitness {
                        if !matches!(bits, 32 | 64) {
                            return Err(invalid("image bitness must be32 or64"));
                        }
                        let legacy = serde_json::from_slice::<Value>(&data)
                            .is_ok_and(|v| v["format"] == "ura-memory-snapshot");
                        if legacy {
                            image.bitness = bits;
                            image.provenance=format!("Imported observed snapshot; CPU mode{bits} is an explicit analyst assumption; missing bytes remain unmapped");
                            engine(image.validate())?;
                        } else if bits != image.bitness {
                            return Err(invalid(
                                "image bitness conflicts with its recorded architecture",
                            ));
                        }
                    }
                    let info = json!({"bitness":image.bitness,"segments":image.segments.iter().map(|s|json!({"base":s.base,"bytes":s.bytes.len(),"permissions":s.permissions})).collect::<Vec<_>>(),"missing":image.missing,"provenance":image.provenance});
                    let id = self.next("image");
                    self.images.insert(id.clone(), image);
                    return Ok(json!({"handle":id,"info":info}));
                }
                let handle = handle.ok_or_else(|| invalid("image handle required"))?;
                if action == "close" {
                    self.images
                        .remove(&handle)
                        .ok_or_else(|| invalid("unknown image handle"))?;
                    return Ok(json!({"closed":handle}));
                }
                let image = self
                    .images
                    .get(&handle)
                    .ok_or_else(|| invalid("unknown image handle"))?;
                match action.as_str() {
                    "info" => Ok(
                        json!({"mode":"capturedImage","bitness":image.bitness,"provenance":image.provenance,"captureMetadata":image.capture_metadata,"missing":image.missing,"segments":image.segments.iter().map(|s|json!({"base":s.base,"bytes":s.bytes.len(),"permissions":s.permissions})).collect::<Vec<_>>(),"portableExecutableReconstructed":false}),
                    ),
                    "analyze" => engine(image.analyze(address(entry, "entry")?)),
                    "memory" => {
                        let address = address(a, "address")?;
                        Ok(
                            json!({"address":Address(address),"bytes":engine(image.read(address,length.unwrap_or(256)))?}),
                        )
                    }
                    "disassembly" => {
                        use ura_core::InstructionDecoder;
                        let address = address(a, "address")?;
                        let bytes = engine(image.read(address, length.unwrap_or(64)))?;
                        let page = ura_core::X86Decoder.decode(
                            &bytes,
                            address,
                            image.bitness,
                            None,
                            128,
                        )?;
                        Ok(json!({"mode":"capturedRuntime","instructions":page.instructions}))
                    }
                    "compare" => {
                        let other = self
                            .images
                            .get(&other.ok_or_else(|| invalid("other image handle required"))?)
                            .ok_or_else(|| invalid("unknown comparison image"))?;
                        engine(image.compare(other, address(a, "address")?, length.unwrap_or(256)))
                    }
                    "export" => self.export(
                        &json!(image),
                        &destination.ok_or_else(|| invalid("destination required"))?,
                    ),
                    _ => Err(invalid("unknown image action")),
                }
            }
        }
    }
}
