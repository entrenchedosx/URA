//! Bounded asynchronous static-analysis jobs. These grants never enable sample
//! execution, debugger attach, live memory access, or implicit file writes.
use crate::{error::ServiceResult, Service, ServiceError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::Write,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::JoinHandle,
};
use ura_core::{
    symbolic::{self, Deobfuscation, Options},
    AnalysisControl,
};

const MAX_RESULT: usize = 24 * 1024 * 1024;
const MAX_PAGE: usize = 1024 * 1024;
#[derive(Default)]
pub(crate) struct SymbolicJobs {
    next: u64,
    jobs: BTreeMap<String, Job>,
}
struct Job {
    handle: String,
    function: u64,
    stamp: String,
    bytes: Arc<Vec<u8>>,
    cancel: Arc<AtomicBool>,
    result: SharedResult,
    thread: Option<JoinHandle<()>>,
}
type SharedResult = Arc<Mutex<Option<Result<Arc<Deobfuscation>, String>>>>;
impl SymbolicJobs {
    pub(crate) fn invalidate_handle(&self, handle: &str) {
        for job in self.jobs.values().filter(|job| job.handle == handle) {
            job.cancel.store(true, Ordering::Release);
        }
    }
}
impl Drop for Job {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
struct Control(Arc<AtomicBool>);
impl AnalysisControl for Control {
    fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
    fn report(&self, _: ura_core::AnalysisProgress) {}
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub action: String,
    pub session: Option<String>,
    pub handle: Option<String>,
    pub function: Option<String>,
    pub options: Option<Options>,
    pub category: Option<String>,
    pub index: Option<usize>,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
    pub destination: Option<String>,
    pub project: Option<String>,
}
fn argument(name: &str) -> ServiceError {
    ServiceError::InvalidArgument(format!("missing or invalid {name}"))
}
fn serialized<T: Serialize>(value: &T) -> ServiceResult<Value> {
    serde_json::to_value(value).map_err(|e| ServiceError::Serialization(e.to_string()))
}
impl Service {
    fn symbolic_stamp(&self, handle: &str, function: u64) -> ServiceResult<String> {
        let session = self
            .sessions
            .get(handle)
            .ok_or_else(|| ServiceError::UnknownHandle(handle.into()))?;
        let analysis = session
            .analysis
            .as_ref()
            .ok_or(ServiceError::AnalysisRequired)?;
        let context = crate::decomp::decomp_context(session, analysis, function);
        let bytes = serde_json::to_vec(&(
            session.analysis_generation,
            &session.info.architecture,
            session.binary.analysis().bitness,
            session.binary.analysis().image_base,
            &session.project,
            &session.manual,
            &context,
            ura_core::ir::IR_VERSION,
            symbolic::ANALYSIS_VERSION,
            env!("CARGO_PKG_VERSION"),
        ))
        .map_err(|e| ServiceError::Serialization(e.to_string()))?;
        Ok(ura_core::sha256_hex(&bytes))
    }
    pub fn symbolic_start(
        &mut self,
        handle: &str,
        function: &str,
        options: Options,
    ) -> ServiceResult<Value> {
        options.validate().map_err(ServiceError::InvalidArgument)?;
        if self.symbolic.jobs.len() >= 4 {
            return Err(ServiceError::LimitExceeded(
                "close a symbolic session before starting another (maximum four)".into(),
            ));
        }
        if self
            .symbolic
            .jobs
            .values()
            .filter(|j| j.result.lock().unwrap_or_else(|e| e.into_inner()).is_none())
            .count()
            >= 2
        {
            return Err(ServiceError::LimitExceeded(
                "maximum two running symbolic sessions".into(),
            ));
        }
        let session = self
            .sessions
            .get(handle)
            .ok_or_else(|| ServiceError::UnknownHandle(handle.into()))?;
        let analysis = session
            .analysis
            .as_ref()
            .ok_or(ServiceError::AnalysisRequired)?;
        let address = ura_core::parse_address(function)?;
        let address = analysis
            .function_containing(address)
            .ok_or_else(|| ServiceError::FunctionNotFound(function.into()))?
            .address;
        let stamp = self.symbolic_stamp(handle, address)?;
        let binary = session.binary.clone();
        let analysis = analysis.clone();
        let context = crate::decomp::decomp_context(session, &analysis, address);
        let bytes = binary.shared_bytes();
        let cancel = Arc::new(AtomicBool::new(false));
        let result = Arc::new(Mutex::new(None));
        let worker_cancel = cancel.clone();
        let worker_result = result.clone();
        let thread = std::thread::Builder::new().name("ura-symbolic".into()).spawn(move || {
            let control = Control(worker_cancel);
            let computed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let bundle = symbolic::deobfuscate(&binary, &analysis, address, &context, &options, &symbolic::solver::IsolatedZ3, &control)?;
                if control.is_cancelled() { return Err("symbolic session cancelled".into()); }
                let size = serde_json::to_vec(&bundle).map_err(|e| e.to_string())?.len();
                if size > MAX_RESULT { return Err("symbolic result exceeds 24MiB retention budget; reduce function/bounds".into()); }
                Ok(Arc::new(bundle))
            })).unwrap_or_else(|_| Err("symbolic worker panicked; no result accepted".into()));
            *worker_result.lock().unwrap_or_else(|e| e.into_inner()) = Some(computed);
        }).map_err(|e| ServiceError::Io(e.to_string()))?;
        self.symbolic.next = self
            .symbolic
            .next
            .checked_add(1)
            .ok_or_else(|| ServiceError::LimitExceeded("symbolic session counter".into()))?;
        let id = format!("sym-{}", self.symbolic.next);
        self.symbolic.jobs.insert(
            id.clone(),
            Job {
                handle: handle.into(),
                function: address,
                stamp,
                bytes,
                cancel,
                result,
                thread: Some(thread),
            },
        );
        Ok(json!({"session":id,"state":"running","function":ura_core::format_address(address)}))
    }
    fn symbolic_current(&self, job: &Job) -> bool {
        let bytes_match = self
            .sessions
            .get(&job.handle)
            .is_some_and(|s| Arc::ptr_eq(&s.binary.shared_bytes(), &job.bytes));
        bytes_match
            && self
                .symbolic_stamp(&job.handle, job.function)
                .is_ok_and(|stamp| stamp == job.stamp)
    }
    fn symbolic_result(&self, id: &str) -> ServiceResult<Arc<Deobfuscation>> {
        let job = self
            .symbolic
            .jobs
            .get(id)
            .ok_or_else(|| argument("symbolic session"))?;
        if job.cancel.load(Ordering::Acquire) {
            return Err(ServiceError::InvalidArgument(
                "symbolic session cancelled".into(),
            ));
        }
        if !self.symbolic_current(job) {
            job.cancel.store(true, Ordering::Release);
            return Err(ServiceError::InvalidArgument("stale symbolic session: effective bytes, processor, analysis generation or decompiler context changed; start a new session".into()));
        }
        let result = job.result.lock().unwrap_or_else(|e| e.into_inner());
        match result.as_ref() {
            None => Err(ServiceError::InvalidArgument(
                "symbolic session still running; poll status".into(),
            )),
            Some(Err(reason)) => Err(ServiceError::InvalidArgument(reason.clone())),
            Some(Ok(bundle)) => Ok(bundle.clone()),
        }
    }
    pub fn symbolic_rpc(&mut self, value: Value) -> ServiceResult<Value> {
        struct RequestBudget(usize);
        impl std::io::Write for RequestBudget {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0 = self.0.saturating_add(bytes.len());
                if self.0 > 65536 {
                    return Err(std::io::Error::other("symbolic request exceeds 64KiB"));
                }
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        serde_json::to_writer(RequestBudget(0), &value)
            .map_err(|_| ServiceError::LimitExceeded("symbolic request exceeds 64KiB".into()))?;
        let request: Request = serde_json::from_value(value)
            .map_err(|e| ServiceError::InvalidArgument(e.to_string()))?;
        if request.action == "start" {
            return self.symbolic_start(
                request
                    .handle
                    .as_deref()
                    .ok_or_else(|| argument("handle"))?,
                request
                    .function
                    .as_deref()
                    .ok_or_else(|| argument("function"))?,
                request.options.unwrap_or_default(),
            );
        }
        if request.action == "load" {
            let project = self.policy.allow_read(Path::new(
                request
                    .project
                    .as_deref()
                    .ok_or_else(|| argument("project"))?,
            ))?;
            let snapshot = ura_project::read_project(&project)?;
            let root: Value = snapshot
                .view_state
                .as_deref()
                .map(serde_json::from_str)
                .transpose()
                .map_err(|e| ServiceError::Serialization(e.to_string()))?
                .unwrap_or(json!({}));
            return bounded(
                json!({"authoritative":false,"state":"historical metadata; reanalysis required before applying any transformation","metadata":root.get("uraSymbolic")}),
            );
        }
        let id = request
            .session
            .as_deref()
            .ok_or_else(|| argument("session"))?;
        if request.action == "close" {
            self.symbolic
                .jobs
                .remove(id)
                .ok_or_else(|| argument("symbolic session"))?;
            return Ok(json!({"session":id,"state":"closed"}));
        }
        let job = self
            .symbolic
            .jobs
            .get(id)
            .ok_or_else(|| argument("symbolic session"))?;
        if request.action == "cancel" {
            job.cancel.store(true, Ordering::Release);
            return Ok(json!({"session":id,"state":"cancelling"}));
        }
        if request.action == "status" {
            let current = self.symbolic_current(job);
            if !current {
                job.cancel.store(true, Ordering::Release);
            }
            let result = job.result.lock().unwrap_or_else(|e| e.into_inner());
            let (state, error) = if !current {
                ("stale", None)
            } else if job.cancel.load(Ordering::Acquire) {
                ("cancelled", None)
            } else {
                match result.as_ref() {
                    None => ("running", None),
                    Some(Ok(_)) => ("complete", None),
                    Some(Err(e)) => ("error", Some(e.clone())),
                }
            };
            return Ok(json!({"session":id,"state":state,"error":error,"current":current}));
        }
        let bundle = self.symbolic_result(id)?;
        let report = &bundle.report;
        match request.action.as_str() {
            "summary" => Ok(
                json!({"session":id,"identity":report.identity,"solver":report.solver,"function":report.function,"processor":bundle.processor,"effectiveSha256":bundle.effective_sha256,"peakStateBytes":report.peak_state_bytes,
                "assumptions":report.assumptions,"predicates":report.predicates.len(),"proofQueries":report.queries.len(),
                "paths":report.paths.len(),"prunedEdges":report.removed_edges.len(),"dispatchers":report.dispatchers.len(),
                "indirectTransfers":report.indirect_targets.len(),"exploredStates":report.explored_states,"operations":report.operations,
                "elapsedUs":report.elapsed_us,"complete":report.complete,"diagnostics":report.diagnostics}),
            ),
            "page" => {
                let offset = request.offset.unwrap_or(0);
                let limit = request.limit.unwrap_or(32);
                if !(1..=64).contains(&limit) {
                    return Err(argument("limit (1..64)"));
                }
                let values = match request.category.as_deref().unwrap_or("predicates") {
                    "predicates" => serialized(&report.predicates)?,
                    "queries" => serialized(&report.queries)?,
                    "paths" => serialized(&report.paths)?,
                    "dispatchers" => serialized(&report.dispatchers)?,
                    "targets" => serialized(&report.indirect_targets)?,
                    "indirectEdges" => serialized(&bundle.logical_indirect_edges)?,
                    "variables" => serialized(&report.variables)?,
                    "edges" => serialized(&report.removed_edges)?,
                    "expressions" => serialized(&report.expressions.nodes)?,
                    "valueSets" => serialized(&bundle.value_sets.facts)?,
                    "original" => serialized(&bundle.original.pseudocode.lines)?,
                    "simplified" => serialized(&bundle.simplified.pseudocode.lines)?,
                    "cfg" => serialized(&bundle.derived_ir.blocks)?,
                    _ => return Err(argument("page category")),
                };
                let values = values
                    .as_array()
                    .ok_or_else(|| ServiceError::Internal("page is not an array".into()))?;
                bounded(
                    json!({"session":id,"total":values.len(),"offset":offset,"limit":limit,"items":values.iter().skip(offset).take(limit).collect::<Vec<_>>()}),
                )
            }
            "proof" => {
                let index = request.index.ok_or_else(|| argument("index"))?;
                let evidence = report
                    .queries
                    .get(index)
                    .ok_or_else(|| argument("proof index"))?;
                bounded(
                    json!({"session":id,"index":index,"evidence":evidence,"replay":report.replay_query(index).map(|_| "digest verified; expression nodes [0,nodeCount) reproduce the typed query").map_err(ServiceError::InvalidArgument)?}),
                )
            }
            "model" => {
                let evidence = report
                    .queries
                    .get(request.index.ok_or_else(|| argument("index"))?)
                    .ok_or_else(|| argument("proof index"))?;
                bounded(
                    json!({"status":evidence.outcome.status,"model":evidence.outcome.model,"scope":"satisfying example for this query; not exhaustive"}),
                )
            }
            "export" => {
                self.require_writes()?;
                let destination = self.policy.allow_write(Path::new(
                    request
                        .destination
                        .as_deref()
                        .ok_or_else(|| argument("destination"))?,
                ))?;
                let bytes = match request.category.as_deref().unwrap_or("report") {
                    "report" => serde_json::to_vec_pretty(report)
                        .map_err(|e| ServiceError::Serialization(e.to_string()))?,
                    "cfg" => serde_json::to_vec_pretty(&bundle.derived_ir)
                        .map_err(|e| ServiceError::Serialization(e.to_string()))?,
                    "original" | "simplified" => {
                        let source = if request.category.as_deref() == Some("original") {
                            &bundle.original
                        } else {
                            &bundle.simplified
                        };
                        source.pseudocode.text().into_bytes()
                    }
                    _ => return Err(argument("export category")),
                };
                if bytes.len() > MAX_RESULT {
                    return Err(ServiceError::LimitExceeded("export size budget".into()));
                }
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&destination)
                    .map_err(|e| ServiceError::Io(e.to_string()))?;
                file.write_all(&bytes)
                    .and_then(|_| file.sync_all())
                    .map_err(|e| ServiceError::Io(e.to_string()))?;
                Ok(
                    json!({"destination":destination,"bytes":bytes.len(),"sha256":ura_core::sha256_hex(&bytes)}),
                )
            }
            "save" => {
                self.require_writes()?;
                let path = self.policy.allow_write(Path::new(
                    request
                        .project
                        .as_deref()
                        .ok_or_else(|| argument("project"))?,
                ))?;
                let snapshot = ura_project::read_project(&path)?;
                let session = self
                    .sessions
                    .get(&job.handle)
                    .ok_or_else(|| argument("handle"))?;
                if !snapshot
                    .project
                    .binary_hash
                    .eq_ignore_ascii_case(&session.info.sha256)
                {
                    return Err(ServiceError::ProjectBinaryMismatch);
                }
                ura_project::merge_view_state_fields(
                    &path,
                    &json!({"uraSymbolic":bundle.historical_metadata(Some(&job.stamp))}),
                )?;
                Ok(
                    json!({"project":path,"saved":true,"authoritative":false,"note":"bounded historical metadata; fresh analysis required"}),
                )
            }
            _ => Err(argument("symbolic action")),
        }
    }
}
fn bounded(value: Value) -> ServiceResult<Value> {
    if serde_json::to_vec(&value)
        .map_err(|e| ServiceError::Serialization(e.to_string()))?
        .len()
        > MAX_PAGE
    {
        Err(ServiceError::LimitExceeded(
            "symbolic response exceeds 1MiB; request fewer records".into(),
        ))
    } else {
        Ok(value)
    }
}
