use crate::{
    bounded,
    bridge::{required, Bridge},
    invalid,
    plugins::{Installed, Registry},
    runtime::Runtime,
    Result,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender},
        Arc, Mutex,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
use ura_service::Service;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Limits {
    pub timeout_ms: u64,
    pub memory_mb: u32,
    pub output_bytes: usize,
    pub api_calls: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            timeout_ms: 30_000,
            memory_mb: 256,
            output_bytes: 262144,
            api_calls: 2000,
        }
    }
}
impl Limits {
    pub fn validate(&self) -> Result<()> {
        if !(10..=120_000).contains(&self.timeout_ms)
            || !(64..=1024).contains(&self.memory_mb)
            || !(1024..=262144).contains(&self.output_bytes)
            || !(1..=10000).contains(&self.api_calls)
        {
            invalid("Script resource bounds exceeded")
        } else {
            Ok(())
        }
    }
}
#[derive(Clone)]
pub struct ExecutionConfig {
    pub enabled: bool,
    pub snippets: bool,
    pub plugin_management: bool,
    pub runtime: Option<Runtime>,
    pub registry: PathBuf,
    pub trusted_scripts: BTreeMap<PathBuf, String>,
    pub capabilities: BTreeSet<String>,
}
impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            snippets: false,
            plugin_management: false,
            runtime: None,
            registry: std::env::var_os("LOCALAPPDATA")
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir)
                .join("URA/extensions"),
            trusted_scripts: BTreeMap::new(),
            capabilities: ["project.read", "analysis.read"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        }
    }
}
impl ExecutionConfig {
    pub fn trust_script(&mut self, path: &Path) -> Result<()> {
        let path = path.canonicalize().map_err(|e| e.to_string())?;
        let bytes = read_script(&path)?;
        self.trusted_scripts
            .insert(path, ura_core::sha256_hex(&bytes));
        Ok(())
    }
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JobResult {
    pub started_at_ms: u128,
    pub plugin_version: Option<String>,
    pub plugin_digest: Option<String>,
    pub parameters: Value,
    pub id: String,
    pub session: String,
    pub handle: String,
    pub state: String,
    pub stdout: String,
    pub stderr: String,
    pub error: Option<String>,
    pub duration_ms: u128,
    pub startup_ms: u128,
    pub api_calls: usize,
    pub findings: Vec<Value>,
    pub value: Value,
    pub project_identity: String,
    pub interpreter: String,
    pub capabilities: BTreeSet<String>,
    pub source_plugin: Option<String>,
    pub output_truncated: bool,
}
struct Job {
    result: Arc<Mutex<JobResult>>,
    cancel: Arc<AtomicBool>,
}
struct Run {
    command: Value,
    job: Arc<Mutex<JobResult>>,
    cancel: Arc<AtomicBool>,
    limits: Limits,
}
enum Command {
    Run(Box<Run>),
    Close,
}
struct Session {
    send: SyncSender<Command>,
    cancel: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    snapshot: Option<tempfile::TempDir>,
    memory: u32,
    handle: String,
    plugin: Option<String>,
}
impl Drop for Session {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        let _ = self.send.try_send(Command::Close);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
pub(crate) struct State {
    sessions: BTreeMap<String, Session>,
    jobs: BTreeMap<String, Job>,
    pub batches: BTreeMap<String, crate::batch::Batch>,
    pub sources: BTreeMap<String, crate::extensionpoints::Source>,
    pub processors: BTreeMap<String, crate::extensionpoints::ProcessorImage>,
}
pub(crate) struct Inner {
    pub service: Arc<Mutex<Service>>,
    pub config: ExecutionConfig,
    pub registry: Registry,
    plugin_lock: Mutex<()>,
    pub(crate) state: Mutex<State>,
    pub(crate) next: AtomicU64,
    shutdown: AtomicBool,
    event_thread: Mutex<Option<JoinHandle<()>>>,
    event_gaps: AtomicU64,
    event_errors: Mutex<std::collections::VecDeque<Value>>,
    events: ura_service::events::EventBus,
}
pub struct ExtensionHost {
    pub(crate) inner: Arc<Inner>,
    pub(crate) owned: bool,
}
impl ExtensionHost {
    pub fn request_shutdown(&self) {
        self.inner.shutdown.store(true, Ordering::Release);
        let inner = self.inner.clone();
        let _ = std::thread::Builder::new()
            .name("ura-extension-stop".into())
            .spawn(move || {
                let state = inner.state.lock().unwrap_or_else(|e| e.into_inner());
                for session in state.sessions.values() {
                    session.cancel.store(true, Ordering::Release);
                }
                for job in state.jobs.values() {
                    job.cancel.store(true, Ordering::Release);
                }
            });
    }
    pub fn new(service: Arc<Mutex<Service>>, config: ExecutionConfig) -> Result<Self> {
        if config
            .capabilities
            .iter()
            .any(|c| !crate::plugins::CAPABILITIES.contains(&c.as_str()))
        {
            return invalid("Unknown host capability");
        }
        let registry = Registry::new(&config.registry)?;
        let events = service
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .events
            .clone();
        let inner = Arc::new(Inner {
            service,
            config,
            registry,
            plugin_lock: Mutex::new(()),
            state: Mutex::new(State {
                sessions: BTreeMap::new(),
                jobs: BTreeMap::new(),
                batches: BTreeMap::new(),
                sources: BTreeMap::new(),
                processors: BTreeMap::new(),
            }),
            next: AtomicU64::new(1),
            shutdown: AtomicBool::new(false),
            event_thread: Mutex::new(None),
            event_gaps: AtomicU64::new(0),
            event_errors: Mutex::new(Default::default()),
            events: events.clone(),
        });
        let weak = Arc::downgrade(&inner);
        let events = inner
            .service
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .events
            .clone();
        let initial_after = events.page(u64::MAX).0;
        let thread = std::thread::Builder::new()
            .name("ura-extension-events".into())
            .spawn(move || {
                let mut after = initial_after;
                loop {
                    events.wait(after, Duration::from_millis(250));
                    let Some(inner) = weak.upgrade() else { break };
                    if inner.shutdown.load(Ordering::Acquire) {
                        break;
                    }
                    let (sequence, gap, rows) = events.page(after);
                    if gap {
                        inner.event_gaps.fetch_add(
                            rows.first()
                                .map_or(1, |r| r.sequence.saturating_sub(after).saturating_sub(1)),
                            Ordering::AcqRel,
                        );
                    }
                    after = sequence;
                    if inner.config.enabled {
                        for event in rows {
                            if event.origin.is_none() {
                                if let Err(e) = dispatch_event(&inner, event.clone()) {
                                    let mut errors = inner
                                        .event_errors
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner());
                                    if errors.len() == 32 {
                                        errors.pop_front();
                                    }
                                    errors.push_back(json!({"sequence":event.sequence,"error":e}));
                                }
                            }
                        }
                    }
                }
            })
            .map_err(|e| e.to_string())?;
        *inner.event_thread.lock().unwrap_or_else(|e| e.into_inner()) = Some(thread);
        Ok(Self { inner, owned: true })
    }
    pub fn rpc(&self, value: Value) -> Result<Value> {
        self.reap();
        if serde_json::to_vec(&value).map_err(|e| e.to_string())?.len() > 65536 {
            return invalid("Extension request exceeds64KiB");
        }
        let operation = required(&value, "operation")?;
        let action = required(&value, "action")?;
        let result = match operation {
            "scripts" => self.scripts(action, &value),
            "plugins" => self.plugins(action, &value),
            "batch" => self.batch(action, &value),
            "processor" => self.processor_rpc(action, &value),
            "image" => self
                .inner
                .service
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .dynamic_rpc(value)
                .map_err(|e| e.to_string()),
            "projects" => {
                let mut service = self.inner.service.lock().unwrap_or_else(|e| e.into_inner());
                match action {
                    "open" => Ok(json!(service
                        .open_binary(
                            Path::new(required(&value, "path")?),
                            value["project"].as_str().map(Path::new)
                        )
                        .map_err(|e| e.to_string())?)),
                    "analyze" => Ok(json!(service
                        .analyze(required(&value, "handle")?, &Default::default())
                        .map_err(|e| e.to_string())?)),
                    "close" => Ok(json!(service
                        .close_binary(required(&value, "handle")?)
                        .map_err(|e| e.to_string())?)),
                    _ => invalid("Unknown project action"),
                }
            }
            "events" => {
                if action != "page" {
                    return invalid("Unknown event action");
                }
                let (sequence, gap, events) =
                    self.inner.events.page(value["after"].as_u64().unwrap_or(0));
                bounded(
                    json!({"sequence":sequence,"gap":gap,"events":events,"dispatchDropped":self.inner.event_gaps.load(Ordering::Acquire),"dispatchErrors":*self.inner.event_errors.lock().unwrap_or_else(|e|e.into_inner())}),
                )
            }
            _ => invalid("Unknown extension operation"),
        };
        bounded(result?)
    }
    fn reap(&self) {
        let sessions = {
            let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
            let ids = state
                .sessions
                .iter()
                .filter(|(_, s)| s.thread.as_ref().is_some_and(|t| t.is_finished()))
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>();
            ids.into_iter()
                .filter_map(|id| state.sessions.remove(&id))
                .collect::<Vec<_>>()
        };
        drop(sessions);
    }
    pub(crate) fn enabled(&self) -> Result<()> {
        if self.inner.config.enabled {
            Ok(())
        } else {
            invalid(
                "Python execution is disabled; explicit trusted-code execution permission required",
            )
        }
    }
    fn scripts(&self, action: &str, p: &Value) -> Result<Value> {
        self.enabled()?;
        match action {
            "open" => {
                let handle = required(p, "handle")?.to_string();
                let limits: Limits =
                    serde_json::from_value(p.get("limits").cloned().unwrap_or(json!({})))
                        .map_err(|e| e.to_string())?;
                limits.validate()?;
                let grants = grants(p, &self.inner.config.capabilities)?;
                self.open_session(handle,grants,None,limits.memory_mb).map(|id|json!({"session":id,"persistentVariables":true,"security":"trusted code; worker is not an OS sandbox"}))
            }
            "run" => {
                let session = required(p, "session")?;
                let (code, filename) = if let Some(path) = p["path"].as_str() {
                    let path = self
                        .inner
                        .service
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .extension_policy()
                        .allow_read(Path::new(path))
                        .map_err(|e| e.to_string())?;
                    let bytes = read_script(&path)?;
                    if self.inner.config.trusted_scripts.get(&path)
                        != Some(&ura_core::sha256_hex(&bytes))
                    {
                        return invalid("Script path/content is not explicitly trusted; configure --trust-script before execution");
                    }
                    (
                        String::from_utf8(bytes).map_err(|e| e.to_string())?,
                        path.to_string_lossy().into_owned(),
                    )
                } else {
                    if !self.inner.config.snippets {
                        return invalid(
                            "Code snippets are disabled; explicit --allow-script-snippets required",
                        );
                    }
                    (
                        required(p, "code")?.to_string(),
                        p["filename"]
                            .as_str()
                            .unwrap_or("<ura-console>")
                            .chars()
                            .take(4096)
                            .collect(),
                    )
                };
                if code.len() > 65536 {
                    return invalid("Script exceeds64KiB");
                }
                let args = p.get("args").cloned().unwrap_or(json!([]));
                if args.as_array().is_none_or(|a| {
                    a.len() > 64 || a.iter().any(|v| v.as_str().is_none_or(|s| s.len() > 4096))
                }) {
                    return invalid("Script argument limits");
                }
                self.queue(
                    session,
                    json!({"protocol":1,"kind":"run","code":code,"filename":filename,"args":args}),
                    p,
                )
            }
            "forget" => {
                let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
                let id = required(p, "job")?;
                if state.jobs.get(id).is_some_and(|j| {
                    j.result.lock().unwrap_or_else(|e| e.into_inner()).state == "running"
                }) {
                    return invalid("Cancel or wait before forgetting a running job");
                }
                state.jobs.remove(id).ok_or("Unknown script job")?;
                state.sources.remove(id);
                Ok(json!({"forgotten":true}))
            }
            "status" | "result" => self.job(required(p, "job")?),
            "cancel" => {
                let state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
                let job = state
                    .jobs
                    .get(required(p, "job")?)
                    .ok_or("Unknown script job")?;
                job.cancel.store(true, Ordering::Release);
                Ok(json!({"cancelling":true}))
            }
            "close" => {
                let session = self
                    .inner
                    .state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .sessions
                    .remove(required(p, "session")?);
                drop(session);
                Ok(json!({"closed":true}))
            }
            "list" => {
                let state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
                Ok(
                    json!({"sessions":state.sessions.keys().collect::<Vec<_>>(),"jobs":state.jobs.keys().collect::<Vec<_>>()}),
                )
            }
            _ => invalid("Unknown script action"),
        }
    }
    fn plugins(&self, action: &str, p: &Value) -> Result<Value> {
        match action {
            "accept" => self.accept_extension(p),
            "list" => self.inner.registry.list(),
            "inspect" => Ok(json!(self.inner.registry.inspect(required(p, "id")?)?)),
            "install" | "enable" | "disable" | "uninstall" => {
                self.enabled()?;
                if !self.inner.config.plugin_management {
                    return invalid("Plugin management is disabled; explicit local management permission required");
                }
                let _lifecycle = self
                    .inner
                    .plugin_lock
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let id = p["id"].as_str().unwrap_or("");
                match action {
                    "install" => {
                        let path = self
                            .inner
                            .service
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .extension_policy()
                            .allow_read(Path::new(required(p, "path")?))
                            .map_err(|e| e.to_string())?;
                        Ok(json!(self.inner.registry.install(&path)?))
                    }
                    "enable" => Ok(json!(self.inner.registry.enable(
                        id,
                        grants(p, &self.inner.config.capabilities)?,
                        p.get("configuration").cloned().unwrap_or(json!({}))
                    )?)),
                    _ => {
                        let sessions: Vec<_> = {
                            let mut state =
                                self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
                            let ids = state
                                .sessions
                                .iter()
                                .filter(|(_, s)| s.plugin.as_deref() == Some(id))
                                .map(|(k, _)| k.clone())
                                .collect::<Vec<_>>();
                            ids.into_iter()
                                .filter_map(|id| state.sessions.remove(&id))
                                .collect()
                        };
                        drop(sessions);
                        if action == "disable" {
                            self.inner.registry.disable(id)?;
                        } else {
                            self.inner.registry.uninstall(id)?;
                        }
                        Ok(json!({"id":id,"enabled":false}))
                    }
                }
            }
            "run" => {
                self.enabled()?;
                let plugin = self.inner.registry.inspect(required(p, "id")?)?;
                let callback = if p["kind"] == "analyzer" {
                    plugin
                        .manifest
                        .analyzer
                        .clone()
                        .ok_or("Plugin has no analyzer")?
                } else if p["kind"] == "loader" {
                    plugin
                        .manifest
                        .loader
                        .clone()
                        .ok_or("Plugin has no loader")?
                } else if p["kind"] == "processor" {
                    plugin
                        .manifest
                        .processor
                        .clone()
                        .ok_or("Plugin has no processor")?
                } else {
                    plugin
                        .manifest
                        .commands
                        .iter()
                        .find(|c| Some(c.id.as_str()) == p["command"].as_str())
                        .map(|c| c.callback.clone())
                        .ok_or("Unknown plugin command")?
                };
                let mut p = p.clone();
                let source = if matches!(p["kind"].as_str(), Some("loader" | "processor")) {
                    Some(self.prepare_source(&mut p, &plugin)?)
                } else {
                    None
                };
                let result = self.run_plugin(plugin, callback, &p, None)?;
                if let Some(source) = source {
                    self.inner
                        .state
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .sources
                        .insert(required(&result, "job")?.into(), source);
                }
                Ok(result)
            }
            _ => invalid("Unknown plugin action"),
        }
    }
    fn open_session(
        &self,
        handle: String,
        grants: BTreeSet<String>,
        plugin: Option<String>,
        memory: u32,
    ) -> Result<String> {
        self.enabled()?;
        self.reap();
        if self.inner.shutdown.load(Ordering::Acquire) {
            return invalid("Extension host is shutting down");
        }
        let runtime = match &self.inner.config.runtime {
            Some(v) => Runtime::new(&v.directory)?,
            None => Runtime::discover()?,
        };
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        if self.inner.shutdown.load(Ordering::Acquire) {
            return invalid("Extension host is shutting down");
        }
        if state.sessions.len() >= 4 {
            return invalid("At most four interpreter sessions");
        }
        let id = format!("py-{}", self.inner.next.fetch_add(1, Ordering::Relaxed));
        let shutdown = Arc::new(AtomicBool::new(false));
        let bridge = Bridge::new(
            self.inner.service.clone(),
            handle.clone(),
            grants,
            plugin.clone(),
            shutdown.clone(),
        )?;
        let (send, recv) = mpsc::sync_channel(1);
        let worker_shutdown = shutdown.clone();
        let thread = std::thread::Builder::new()
            .name("ura-python".into())
            .spawn(move || worker(runtime, memory, bridge, worker_shutdown, recv))
            .map_err(|e| e.to_string())?;
        state.sessions.insert(
            id.clone(),
            Session {
                send,
                cancel: shutdown,
                thread: Some(thread),
                snapshot: None,
                memory,
                handle,
                plugin,
            },
        );
        Ok(id)
    }
    fn queue(&self, session: &str, command: Value, p: &Value) -> Result<Value> {
        let limits: Limits = serde_json::from_value(p.get("limits").cloned().unwrap_or(json!({})))
            .map_err(|e| e.to_string())?;
        limits.validate()?;
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        if state
            .jobs
            .values()
            .filter(|j| j.result.lock().unwrap_or_else(|e| e.into_inner()).state == "running")
            .count()
            >= 2
        {
            return invalid("At most two running Python jobs");
        }
        while state.jobs.len() >= 16 {
            let id = state
                .jobs
                .iter()
                .find(|(_, j)| {
                    let r = j.result.lock().unwrap_or_else(|e| e.into_inner());
                    r.source_plugin.is_some() && r.state != "running"
                })
                .map(|(id, _)| id.clone());
            if let Some(id) = id {
                state.jobs.remove(&id);
                state.sources.remove(&id);
            } else {
                break;
            }
        }
        if state.jobs.len() >= 16 {
            return invalid(
                "At most16 retained script jobs; close completed jobs/session or reset host",
            );
        }
        let s = state
            .sessions
            .get(session)
            .ok_or("Unknown interpreter session")?;
        if limits.memory_mb != s.memory {
            return invalid("Job memoryMb must equal the interpreter session memoryMb");
        }
        if s.cancel.load(Ordering::Acquire) {
            return invalid("Interpreter stopped; open a new session");
        }
        if state.jobs.values().any(|j| {
            let r = j.result.lock().unwrap_or_else(|e| e.into_inner());
            r.session == session && r.state == "running"
        }) {
            return invalid("Interpreter is already running");
        }
        let id = format!("script-{}", self.inner.next.fetch_add(1, Ordering::Relaxed));
        let cancel = Arc::new(AtomicBool::new(false));
        let job = Arc::new(Mutex::new(JobResult {
            started_at_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            plugin_version: None,
            plugin_digest: None,
            parameters: Value::Null,
            id: id.clone(),
            session: session.into(),
            handle: s.handle.clone(),
            state: "running".into(),
            stdout: String::new(),
            stderr: String::new(),
            error: None,
            duration_ms: 0,
            startup_ms: 0,
            api_calls: 0,
            findings: Vec::new(),
            value: Value::Null,
            project_identity: String::new(),
            interpreter: crate::runtime::PYTHON_VERSION.into(),
            capabilities: BTreeSet::new(),
            source_plugin: s.plugin.clone(),
            output_truncated: false,
        }));
        s.send
            .try_send(Command::Run(Box::new(Run {
                command,
                job: job.clone(),
                cancel: cancel.clone(),
                limits,
            })))
            .map_err(|_| "Interpreter command queue full or worker exited".to_string())?;
        state.jobs.insert(
            id.clone(),
            Job {
                result: job,
                cancel,
            },
        );
        Ok(json!({"job":id,"session":session,"state":"running"}))
    }
    pub fn job(&self, id: &str) -> Result<Value> {
        let state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        let job = state.jobs.get(id).ok_or("Unknown script job")?;
        let result = job.result.lock().unwrap_or_else(|e| e.into_inner()).clone();
        drop(state);
        let status = if result.handle.is_empty() {
            "detached"
        } else {
            match self.inner.service.try_lock() {
                Ok(service) => {
                    if service
                        .extension_identity(&result.handle)
                        .is_ok_and(|identity| identity == result.project_identity)
                    {
                        "current"
                    } else {
                        "stale"
                    }
                }
                Err(_) => "notCheckedServiceBusy",
            }
        };
        let mut value = json!(result);
        value["identityStatus"] = json!(status);
        bounded(value)
    }
    fn run_plugin(
        &self,
        plugin: Installed,
        callback: String,
        p: &Value,
        event: Option<Value>,
    ) -> Result<Value> {
        let _lifecycle = self
            .inner
            .plugin_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let (plugin, snapshot) = self.inner.registry.snapshot(&plugin.manifest.id)?;
        if !plugin.enabled {
            return invalid("Plugin is disabled or changed since enablement");
        }
        let grant = plugin.grants.as_ref().ok_or("Plugin grant missing")?;
        let cap = match p["kind"].as_str() {
            Some("loader") => Some("loader.register"),
            Some("processor") => Some("processor.register"),
            Some("analyzer") => Some("analysis.read"),
            _ if event.is_none() => Some("ui.commands"),
            _ => None,
        };
        if cap.is_some_and(|cap| !grant.capabilities.contains(cap)) {
            return invalid("Plugin callback capability was not explicitly granted");
        }
        if !grant
            .capabilities
            .is_subset(&self.inner.config.capabilities)
        {
            return invalid("Persisted plugin grants exceed this host's explicit permissions");
        }
        let mut detached = event
            .as_ref()
            .is_some_and(|e| e["kind"] == "project.closed")
            || matches!(p["kind"].as_str(), Some("loader" | "processor"));
        let mut handle = if detached {
            String::new()
        } else {
            required(p, "handle")?.to_string()
        };
        let metadata = if detached {
            json!({})
        } else {
            let service = self
                .inner
                .service
                .try_lock()
                .map_err(|_| "Analysis service busy; retry plugin admission")?;
            match service.extension_metadata(&handle) {
                Ok(v) => {
                    if event
                        .as_ref()
                        .is_some_and(|e| e["generation"] != v["generation"])
                    {
                        detached = true;
                        handle.clear();
                        json!({})
                    } else {
                        v
                    }
                }
                Err(_) if event.is_some() => {
                    detached = true;
                    handle.clear();
                    json!({})
                }
                Err(e) => return Err(e.to_string()),
            }
        };
        let processor = metadata["binary"]["architecture"].as_str().unwrap_or("");
        if !detached
            && !plugin
                .manifest
                .architectures
                .iter()
                .any(|a| a == processor || (a == "aarch64" && processor == "arm64"))
        {
            return invalid("Plugin does not declare the selected binary architecture");
        }
        let limits: Limits = serde_json::from_value(p.get("limits").cloned().unwrap_or(json!({})))
            .map_err(|e| e.to_string())?;
        limits.validate()?;
        let session = self.open_session(
            handle,
            grant.capabilities.clone(),
            Some(plugin.manifest.id.clone()),
            limits.memory_mb,
        )?;
        let command = json!({"protocol":1,"kind":"run","detached":detached,"plugin":snapshot.path(),"pluginId":plugin.manifest.id,"entrypoint":plugin.manifest.entrypoint,"callback":callback,"parameters":p.get("parameters").cloned().unwrap_or(json!({})),"configuration":grant.configuration,"event":event});
        self.inner
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sessions
            .get_mut(&session)
            .ok_or("Plugin interpreter missing")?
            .snapshot = Some(snapshot);
        match self.queue(&session, command, p) {
            Ok(v) => {
                let state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(job) = v["job"].as_str().and_then(|id| state.jobs.get(id)) {
                    let mut r = job.result.lock().unwrap_or_else(|e| e.into_inner());
                    r.plugin_version = Some(plugin.manifest.version.clone());
                    r.plugin_digest = Some(plugin.digest.clone());
                    let params = p.get("parameters").cloned().unwrap_or(json!({}));
                    let bytes = serde_json::to_vec(&params).map_err(|e| e.to_string())?;
                    r.parameters = if bytes.len() <= 8192 {
                        params
                    } else {
                        json!({"partial":true,"bytes":bytes.len(),"sha256":ura_core::sha256_hex(&bytes)})
                    };
                }
                Ok(v)
            }
            Err(e) => {
                let session = self
                    .inner
                    .state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .sessions
                    .remove(&session);
                drop(session);
                Err(e)
            }
        }
    }
}
fn grants(p: &Value, allowed: &BTreeSet<String>) -> Result<BTreeSet<String>> {
    let set: BTreeSet<String> = serde_json::from_value(
        p.get("capabilities")
            .cloned()
            .unwrap_or(json!(["project.read", "analysis.read"])),
    )
    .map_err(|e| e.to_string())?;
    if !set.is_subset(allowed) {
        invalid("Requested capabilities exceed startup grants")
    } else {
        Ok(set)
    }
}
fn read_script(path: &Path) -> Result<Vec<u8>> {
    let f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    f.take(65537)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 65536 {
        invalid("Script file exceeds64KiB")
    } else {
        Ok(bytes)
    }
}
fn dispatch_event(inner: &Arc<Inner>, event: ura_service::events::AnalysisEvent) -> Result<()> {
    if event.handle.is_empty() {
        return Ok(());
    }
    let rows = inner.registry.list()?;
    for row in rows["plugins"]
        .as_array()
        .ok_or("Invalid plugin inventory")?
    {
        let Some(id) = row["manifest"]["id"].as_str() else {
            continue;
        };
        let plugin = inner.registry.inspect(id)?;
        if !plugin.enabled {
            continue;
        }
        let Some(callback) = plugin.manifest.events.get(&event.kind).cloned() else {
            continue;
        };
        if !plugin
            .grants
            .as_ref()
            .is_some_and(|g| g.capabilities.contains("events.subscribe"))
        {
            continue;
        }

        let host = ExtensionHost {
            inner: inner.clone(),
            owned: false,
        };
        host.reap();
        let started = Instant::now();
        let result = loop {
            if inner.shutdown.load(Ordering::Acquire) {
                return Ok(());
            }
            let r = host.run_plugin(
                plugin.clone(),
                callback.clone(),
                &json!({"handle":event.handle,"limits":{"timeoutMs":5000}}),
                Some(json!(event)),
            );
            if r.as_ref().err().is_some_and(|e| e.contains("busy"))
                && started.elapsed() < Duration::from_secs(5)
            {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            break r;
        };
        if let Err(e) = &result {
            return Err(format!("Plugin {id} event admission failed: {e}"));
        }
        if let Ok(job) = result {
            let job = job["job"].as_str().ok_or("Missing event job")?;
            loop {
                if inner.shutdown.load(Ordering::Acquire) {
                    break;
                }
                if host.job(job)?["state"] != "running" {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
    Ok(())
}
impl Drop for ExtensionHost {
    fn drop(&mut self) {
        if !self.owned {
            return;
        }
        self.inner.shutdown.store(true, Ordering::Release);
        let sessions = std::mem::take(
            &mut self
                .inner
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .sessions,
        );
        drop(sessions);
        let batches = std::mem::take(
            &mut self
                .inner
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .batches,
        );
        drop(batches);
        if let Some(thread) = self
            .inner
            .event_thread
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = thread.join();
        }
    }
}

type WireMessage = (Vec<u8>, SyncSender<Result<()>>);
struct Wire {
    send: Option<SyncSender<WireMessage>>,
    thread: Option<JoinHandle<()>>,
}
impl Wire {
    fn new(mut pipe: std::process::ChildStdin) -> Result<Self> {
        let (send, recv) = mpsc::sync_channel::<WireMessage>(1);
        let thread = std::thread::Builder::new()
            .name("ura-python-input".into())
            .spawn(move || {
                while let Ok((line, ack)) = recv.recv() {
                    let r = pipe
                        .write_all(&line)
                        .and_then(|_| pipe.write_all(b"\n"))
                        .and_then(|_| pipe.flush())
                        .map_err(|e| e.to_string());
                    let failed = r.is_err();
                    if ack.send(r).is_err() || failed {
                        break;
                    }
                }
            })
            .map_err(|e| e.to_string())?;
        Ok(Self {
            send: Some(send),
            thread: Some(thread),
        })
    }
    fn send(
        &self,
        value: &Value,
        shutdown: &AtomicBool,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<()> {
        let line = serde_json::to_vec(value).map_err(|e| e.to_string())?;
        if line.len() > 1024 * 1024 {
            return invalid("Worker command too large");
        }
        let (send, recv) = mpsc::sync_channel(1);
        self.send
            .as_ref()
            .ok_or("Worker input closed")?
            .try_send((line, send))
            .map_err(|_| "Worker input queue full/closed".to_string())?;
        loop {
            if shutdown.load(Ordering::Acquire)
                || cancel.load(Ordering::Acquire)
                || Instant::now() >= deadline
            {
                return invalid("Worker input deadline/cancellation; terminating interpreter");
            }
            match recv.recv_timeout(Duration::from_millis(5)) {
                Ok(r) => return r,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(_) => return invalid("Worker input writer stopped"),
            }
        }
    }
}
impl Drop for Wire {
    fn drop(&mut self) {
        self.send.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
fn worker(
    runtime: Runtime,
    memory: u32,
    bridge: Bridge,
    shutdown: Arc<AtomicBool>,
    commands: Receiver<Command>,
) {
    let detached = bridge.handle.is_empty();
    let bridge = Arc::new(Mutex::new(bridge));
    let start = Instant::now();
    let spawned = (|| -> Result<_> {
        let folder = Runtime::worker_sources()?;
        let mut command = std::process::Command::new(runtime.executable());
        command
            .args(["-I", "-S", "-B", "-u"])
            .arg(folder.path().join("worker.py"))
            .current_dir(folder.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let mut child = command.spawn().map_err(|e| e.to_string())?;
        let job = match crate::process::attach(&child, memory) {
            Ok(v) => v,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        };
        let wire = Wire::new(child.stdin.take().ok_or("Missing Python input")?)?;
        let stdout = child.stdout.take().ok_or("Missing Python output")?;
        let stderr = child.stderr.take().ok_or("Missing Python stderr")?;
        let (send, receive) = mpsc::sync_channel(8);
        let reader = std::thread::spawn(move || {
            let mut input = BufReader::new(stdout);
            loop {
                let mut bytes = Vec::new();
                let read = Read::take(&mut input, 1024 * 1024 + 1).read_until(b'\n', &mut bytes);
                let result = match read {
                    Ok(0) => Err("Python worker exited".into()),
                    Ok(_) if bytes.len() <= 1024 * 1024 && bytes.last() == Some(&b'\n') => {
                        serde_json::from_slice::<Value>(&bytes)
                            .map_err(|e| format!("Invalid worker protocol: {e}"))
                    }
                    _ => Err("Worker output line limit/error".into()),
                };
                let done = result.is_err();
                if send.send(result).is_err() || done {
                    break;
                }
            }
        });
        let errors = Arc::new(Mutex::new(String::new()));
        let error_copy = errors.clone();
        let error_reader = std::thread::spawn(move || {
            let mut input = stderr;
            let mut block = [0; 4096];
            while let Ok(n) = input.read(&mut block) {
                if n == 0 {
                    break;
                }
                let mut out = error_copy.lock().unwrap_or_else(|e| e.into_inner());
                if out.len() < 65536 {
                    let remain = 65536 - out.len();
                    out.push_str(&String::from_utf8_lossy(&block[..n.min(remain)]));
                }
            }
        });
        Ok((
            folder,
            child,
            job,
            wire,
            receive,
            reader,
            errors,
            error_reader,
        ))
    })();
    let (folder, mut child, job, wire, receive, reader, errors, error_reader) = match spawned {
        Ok(v) => v,
        Err(e) => {
            loop {
                match commands.recv_timeout(Duration::from_millis(100)) {
                    Ok(Command::Close) => break,
                    Ok(Command::Run(run)) => {
                        fail(&run.job, "workerError", &e, start.elapsed().as_millis())
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if shutdown.load(Ordering::Acquire) {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            return;
        }
    };
    let ready = receive.recv_timeout(Duration::from_secs(10));
    let startup = start.elapsed().as_millis();
    let valid = matches!(ready,Ok(Ok(ref v)) if v["protocol"]==1 && v["kind"]=="ready" && v["python"]==crate::runtime::PYTHON_VERSION && v["bits"]==64 && v["sdk"]==crate::SDK_VERSION);
    if !valid {
        shutdown.store(true, Ordering::Release);
    }
    loop {
        let command = match commands.recv_timeout(Duration::from_millis(100)) {
            Ok(v) => v,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if shutdown.load(Ordering::Acquire) {
                    break;
                }
                continue;
            }
            Err(_) => break,
        };
        let Command::Run(run) = command else { break };
        let started = Instant::now();
        if !valid || shutdown.load(Ordering::Acquire) {
            fail(
                &run.job,
                "workerError",
                "Interpreter unavailable; open a new session",
                0,
            );
            break;
        }
        {
            let mut b = bridge.lock().unwrap_or_else(|e| e.into_inner());
            b.cancel = run.cancel.clone();
            b.deadline = Some(Instant::now() + Duration::from_millis(run.limits.timeout_ms));
            b.findings.clear();
            let mut r = run.job.lock().unwrap_or_else(|e| e.into_inner());
            r.startup_ms = startup;
            r.project_identity = b.identity.clone();
            r.capabilities = b.grants.clone();
        }
        if let Err(e) = wire.send(
            &run.command,
            &shutdown,
            &run.cancel,
            started + Duration::from_millis(run.limits.timeout_ms),
        ) {
            fail(
                &run.job,
                if run.cancel.load(Ordering::Acquire) {
                    "cancelled"
                } else if started.elapsed().as_millis() >= u128::from(run.limits.timeout_ms) {
                    "timeout"
                } else {
                    "workerError"
                },
                &e,
                started.elapsed().as_millis(),
            );
            break;
        }
        let mut calls = 0;
        let mut output = 0;
        let mut ended = false;
        while !ended {
            let reason = if shutdown.load(Ordering::Acquire) || run.cancel.load(Ordering::Acquire) {
                Some((
                    "cancelled",
                    "Script cancelled; interpreter session terminated",
                ))
            } else if started.elapsed().as_millis() >= u128::from(run.limits.timeout_ms) {
                Some((
                    "timeout",
                    "Script wall deadline exceeded; interpreter session terminated",
                ))
            } else {
                None
            };
            if let Some((state, error)) = reason {
                fail(&run.job, state, error, started.elapsed().as_millis());
                shutdown.store(true, Ordering::Release);
                break;
            }
            let message = match receive.recv_timeout(Duration::from_millis(10)) {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    fail(&run.job, "crashed", &e, started.elapsed().as_millis());
                    shutdown.store(true, Ordering::Release);
                    break;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(_) => {
                    fail(
                        &run.job,
                        "crashed",
                        "Worker output closed",
                        started.elapsed().as_millis(),
                    );
                    shutdown.store(true, Ordering::Release);
                    break;
                }
            };
            if message["protocol"] != 1 {
                fail(
                    &run.job,
                    "protocolError",
                    "Protocol version mismatch",
                    started.elapsed().as_millis(),
                );
                shutdown.store(true, Ordering::Release);
                break;
            }
            match message["kind"].as_str() {
                Some("output") => {
                    let text = message["text"].as_str().unwrap_or("");
                    output += serde_json::to_vec(text).map_or(usize::MAX / 2, |b| b.len());
                    if output > run.limits.output_bytes {
                        let mut r = run.job.lock().unwrap_or_else(|e| e.into_inner());
                        r.output_truncated = true;
                        drop(r);
                        fail(
                            &run.job,
                            "outputLimit",
                            "Script output limit exceeded",
                            started.elapsed().as_millis(),
                        );
                        shutdown.store(true, Ordering::Release);
                        break;
                    }
                    let mut r = run.job.lock().unwrap_or_else(|e| e.into_inner());
                    if message["channel"] == "stdout" {
                        r.stdout.push_str(text);
                    } else {
                        r.stderr.push_str(text);
                    }
                }
                Some("call") => {
                    calls += 1;
                    if calls > run.limits.api_calls {
                        fail(
                            &run.job,
                            "apiLimit",
                            "Script API-call budget exceeded",
                            started.elapsed().as_millis(),
                        );
                        shutdown.store(true, Ordering::Release);
                        break;
                    }
                    let result = if let (Some(method), true) =
                        (message["method"].as_str(), message["params"].is_object())
                    {
                        match api_call(
                            bridge.clone(),
                            method.to_owned(),
                            message["params"].clone(),
                            &shutdown,
                            &run,
                            started,
                        ) {
                            Ok(v) => v,
                            Err(e) => {
                                fail(
                                    &run.job,
                                    "timeoutOrCancelled",
                                    &e,
                                    started.elapsed().as_millis(),
                                );
                                run.cancel.store(true, Ordering::Release);
                                shutdown.store(true, Ordering::Release);
                                break;
                            }
                        }
                    } else {
                        invalid("Malformed worker API request")
                    };
                    let response = match result {
                        Ok(result) => json!({"protocol":1,"id":message["id"],"result":result}),
                        Err(error) => json!({"protocol":1,"id":message["id"],"error":error}),
                    };
                    if let Err(e) = wire.send(
                        &response,
                        &shutdown,
                        &run.cancel,
                        started + Duration::from_millis(run.limits.timeout_ms),
                    ) {
                        fail(
                            &run.job,
                            if run.cancel.load(Ordering::Acquire) {
                                "cancelled"
                            } else if started.elapsed().as_millis()
                                >= u128::from(run.limits.timeout_ms)
                            {
                                "timeout"
                            } else {
                                "workerError"
                            },
                            &e,
                            started.elapsed().as_millis(),
                        );
                        shutdown.store(true, Ordering::Release);
                        break;
                    }
                }
                Some("done") => {
                    if !detached {
                        match api_call(
                            bridge.clone(),
                            "__validate".into(),
                            json!({}),
                            &shutdown,
                            &run,
                            started,
                        ) {
                            Ok(Ok(_)) => {}
                            Ok(Err(e)) => {
                                fail(&run.job,"stale",&format!("Project changed/closed; findings and result discarded: {e}"),started.elapsed().as_millis());
                                break;
                            }
                            Err(e) => {
                                fail(
                                    &run.job,
                                    "timeoutOrCancelled",
                                    &e,
                                    started.elapsed().as_millis(),
                                );
                                run.cancel.store(true, Ordering::Release);
                                shutdown.store(true, Ordering::Release);
                                break;
                            }
                        }
                    }
                    let bridge = bridge.lock().unwrap_or_else(|e| e.into_inner());
                    if serde_json::to_vec(&message["result"]).map_or(true, |b| b.len() > 262144) {
                        fail(
                            &run.job,
                            "resultLimit",
                            "Plugin result exceeds256KiB",
                            started.elapsed().as_millis(),
                        );
                        break;
                    }
                    let mut r = run.job.lock().unwrap_or_else(|e| e.into_inner());
                    r.error = message["error"].as_str().map(str::to_owned);
                    r.state = if r.error.is_some() {
                        "pythonError"
                    } else {
                        "complete"
                    }
                    .into();
                    r.value = message["result"].clone();
                    r.duration_ms = started.elapsed().as_millis();
                    r.api_calls = calls;
                    r.findings = bridge.findings.clone();
                    r.project_identity = bridge.identity.clone();
                    ended = true;
                }
                _ => {
                    fail(
                        &run.job,
                        "protocolError",
                        "Unexpected worker message",
                        started.elapsed().as_millis(),
                    );
                    shutdown.store(true, Ordering::Release);
                    break;
                }
            }
        }
        if run.command.get("plugin").is_some() {
            shutdown.store(true, Ordering::Release);
        }
        if shutdown.load(Ordering::Acquire) {
            break;
        }
    }
    shutdown.store(true, Ordering::Release);
    let _ = child.kill();
    drop(job);
    let _ = child.wait();
    drop(wire);
    drop(receive);
    let _ = reader.join();
    let _ = error_reader.join();
    drop(errors);
    drop(folder);
}
fn fail(job: &Arc<Mutex<JobResult>>, state: &str, error: &str, duration: u128) {
    let mut result = job.lock().unwrap_or_else(|e| e.into_inner());
    result.state = state.into();
    result.error = Some(error.chars().take(16384).collect());
    result.duration_ms = duration;
}

static API_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
struct ApiPermit;
impl Drop for ApiPermit {
    fn drop(&mut self) {
        API_CALLS.fetch_sub(1, Ordering::AcqRel);
    }
}
fn api_call(
    bridge: Arc<Mutex<Bridge>>,
    method: String,
    p: Value,
    shutdown: &AtomicBool,
    run: &Run,
    start: Instant,
) -> Result<Result<Value>> {
    if API_CALLS
        .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n < 4).then_some(n + 1)
        })
        .is_err()
    {
        return Ok(invalid(
            "Four host API calls are still in flight; retry after they finish",
        ));
    }
    let permit = ApiPermit;
    let (send, recv) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("ura-sdk-call".into())
        .spawn(move || {
            let _permit = permit;
            let r = bridge
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .call(&method, p);
            let _ = send.send(r);
        })
        .map_err(|e| e.to_string())?;
    loop {
        if shutdown.load(Ordering::Acquire)
            || run.cancel.load(Ordering::Acquire)
            || start.elapsed().as_millis() >= u128::from(run.limits.timeout_ms)
        {
            return invalid("Python supervisor deadline/cancellation; already admitted bounded host calls finish independently");
        }
        match recv.recv_timeout(Duration::from_millis(5)) {
            Ok(r) => return Ok(r),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(_) => return invalid("Host API task failed"),
        }
    }
}
