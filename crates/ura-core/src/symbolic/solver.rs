//! Real Z3 bit-vector/array queries. Product callers use `IsolatedZ3`; the direct
//! backend is public for headless library hosts that provide their own isolation.
use super::expr::{Arena, Id, Kind, Sort};
use crate::{ir::Operation, AnalysisControl};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, time::Instant};
use z3::{
    ast::{Array, Bool, BV},
    Config, Params, SatResult, Solver,
};

pub const WORKER_FLAG: &str = "--ura-smt-worker";
pub const MAX_REQUEST: usize = 12 * 1024 * 1024;
pub const MAX_RESPONSE: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Status {
    Sat,
    Unsat,
    Unknown,
    Timeout,
    Unsupported,
    Error,
    Cancelled,
    Limit,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Limits {
    pub timeout_ms: u32,
    pub resource_limit: u32,
    pub memory_mb: u32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            timeout_ms: 500,
            resource_limit: 2_000_000,
            memory_mb: 256,
        }
    }
}
impl Limits {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=10_000).contains(&self.timeout_ms)
            || !(1..=50_000_000).contains(&self.resource_limit)
            || !(64..=1024).contains(&self.memory_mb)
        {
            return Err("invalid solver limits".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Query {
    pub arena: Arena,
    pub assertions: Vec<Id>,
    pub observables: BTreeMap<String, Id>,
    pub limits: Limits,
}
impl Query {
    fn validate(&mut self) -> Result<(), String> {
        self.limits.validate()?;
        self.arena.rebuild()?;
        if self.assertions.len() > 1024 || self.observables.len() > 256 {
            return Err("query result/constraint budget exceeded".into());
        }
        for id in &self.assertions {
            if self.arena.sort(*id)? != Sort::Bits(1) {
                return Err("assertion is not boolean".into());
            }
        }
        for (name, id) in &self.observables {
            if name.len() > 128 || name.contains('\0') || self.arena.sort(*id)?.width().is_none() {
                return Err("invalid scalar observable".into());
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Outcome {
    pub status: Status,
    pub model: BTreeMap<String, crate::ir::Address>,
    pub reason: Option<String>,
    pub elapsed_us: u64,
    pub solver: String,
}
impl Outcome {
    pub fn stopped(status: Status, reason: impl Into<String>) -> Self {
        Self {
            status,
            model: BTreeMap::new(),
            reason: Some(reason.into()),
            elapsed_us: 0,
            solver: format!("Z3 {}", z3::full_version()),
        }
    }
}
pub trait Backend {
    fn query(&self, query: Query, control: &dyn AnalysisControl) -> Outcome;
}
pub struct DirectZ3;
impl Backend for DirectZ3 {
    fn query(&self, mut query: Query, control: &dyn AnalysisControl) -> Outcome {
        let start = Instant::now();
        if control.is_cancelled() {
            return Outcome::stopped(Status::Cancelled, "cancelled before query");
        }
        if let Err(error) = query.validate() {
            return Outcome::stopped(Status::Error, error);
        }
        if query
            .assertions
            .iter()
            .chain(query.observables.values())
            .any(|i| query.arena.is_poisoned(*i))
        {
            return Outcome::stopped(
                Status::Unsupported,
                "query depends on unknown or undefined machine state",
            );
        }
        let mut config = Config::new();
        config.set_timeout_msec(u64::from(query.limits.timeout_ms));
        let mut result = z3::with_z3_config(&config, || solve(&query));
        result.elapsed_us = start.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        if control.is_cancelled() {
            return Outcome::stopped(Status::Cancelled, "cancelled during query");
        }
        result
    }
}
enum Value {
    Bits(BV),
    Memory(Array),
}
impl Value {
    fn bits(&self) -> &BV {
        match self {
            Self::Bits(b) => b,
            _ => unreachable!("validated scalar sort"),
        }
    }
    fn memory(&self) -> &Array {
        match self {
            Self::Memory(m) => m,
            _ => unreachable!("validated memory sort"),
        }
    }
}
fn boolean(value: Bool) -> BV {
    value.ite(&BV::from_u64(1, 1), &BV::from_u64(0, 1))
}
fn solve(query: &Query) -> Outcome {
    let mut values: Vec<Value> = Vec::with_capacity(query.arena.nodes.len());
    for node in &query.arena.nodes {
        let width = u32::from(node.sort.width().unwrap_or(0));
        let value = match &node.kind {
            Kind::Constant { value } => Value::Bits(BV::from_u64(value.0, width)),
            Kind::Symbol { name, .. } => match node.sort {
                Sort::Bits(w) => Value::Bits(BV::new_const(name.as_str(), u32::from(w))),
                Sort::Memory(w) => Value::Memory(Array::new_const(
                    name.as_str(),
                    &z3::Sort::bitvector(u32::from(w)),
                    &z3::Sort::bitvector(8),
                )),
            },
            Kind::ArithmeticShiftRight { value, count } => {
                Value::Bits(values[*value].bits().bvashr(values[*count].bits()))
            }
            Kind::Concat { high, low } => {
                Value::Bits(values[*high].bits().concat(values[*low].bits()))
            }
            Kind::Load { memory, address } => {
                let m = values[*memory].memory();
                let a = values[*address].bits();
                let mut result = m.select(a).as_bv().expect("byte array");
                for byte in 1..width / 8 {
                    let index = a.bvadd(BV::from_u64(u64::from(byte), a.get_size()));
                    result = m
                        .select(&index)
                        .as_bv()
                        .expect("byte array")
                        .concat(&result);
                }
                Value::Bits(result)
            }
            Kind::Store {
                memory,
                address,
                value,
            } => {
                let mut result = values[*memory].memory().clone();
                let a = values[*address].bits();
                let v = values[*value].bits();
                for byte in 0..v.get_size() / 8 {
                    let index = a.bvadd(BV::from_u64(u64::from(byte), a.get_size()));
                    result = result.store(&index, &v.extract(byte * 8 + 7, byte * 8));
                }
                Value::Memory(result)
            }
            Kind::Pure { operation, inputs } => {
                let args: Vec<_> = inputs.iter().map(|i| values[*i].bits()).collect();
                match scalar(operation, width, &args) {
                    Ok(v) => Value::Bits(v),
                    Err(e) => return Outcome::stopped(Status::Unsupported, e),
                }
            }
        };
        values.push(value);
    }
    let solver = Solver::new();
    let mut params = Params::new();
    params.set_u32("timeout", query.limits.timeout_ms);
    params.set_u32("rlimit", query.limits.resource_limit);
    solver.set_params(&params);
    for id in &query.assertions {
        solver.assert(values[*id].bits().eq(BV::from_u64(1, 1)));
    }
    let mut result = Outcome::stopped(Status::Unknown, "solver returned no result");
    result.reason = None;
    match solver.check() {
        SatResult::Sat => {
            result.status = Status::Sat;
            let Some(model) = solver.get_model() else {
                return Outcome::stopped(Status::Error, "SAT without model");
            };
            for (name, id) in &query.observables {
                let Some(value) = model
                    .eval(values[*id].bits(), true)
                    .and_then(|v| v.as_u64())
                else {
                    return Outcome::stopped(Status::Error, "non-numeral scalar model");
                };
                result.model.insert(name.clone(), crate::ir::Address(value));
            }
        }
        SatResult::Unsat => result.status = Status::Unsat,
        SatResult::Unknown => {
            let reason = solver
                .get_reason_unknown()
                .unwrap_or_else(|| "unknown".into());
            result.status = if reason.contains("timeout") {
                Status::Timeout
            } else {
                Status::Unknown
            };
            result.reason = Some(reason.chars().take(1024).collect());
        }
    }
    result
}
fn scalar(op: &Operation, width: u32, a: &[&BV]) -> Result<BV, String> {
    use Operation::*;
    let x = a[0];
    let result = match op {
        Copy => x.clone(),
        Add => x.bvadd(a[1]),
        Sub => x.bvsub(a[1]),
        Mul => x.bvmul(a[1]),
        And => x.bvand(a[1]),
        Or => x.bvor(a[1]),
        Xor => x.bvxor(a[1]),
        Not => x.bvnot(),
        Shl => x.bvshl(a[1]),
        Shr => x.bvlshr(a[1]),
        RotateLeft => x.bvrotl(a[1]),
        RotateRight => x.bvrotr(a[1]),
        Equal => boolean(x.eq(a[1])),
        UnsignedLess => boolean(x.bvult(a[1])),
        SignedLess => boolean(x.bvslt(a[1])),
        ZeroExtend => x.zero_ext(width - x.get_size()),
        SignExtend => x.sign_ext(width - x.get_size()),
        Truncate => x.extract(width - 1, 0),
        Extract { offset } => x.extract(u32::from(*offset) + width - 1, u32::from(*offset)),
        Insert { offset } => {
            let offset = u32::from(*offset);
            let end = offset + a[1].get_size();
            let mut v = a[1].clone();
            if offset > 0 {
                v = v.concat(x.extract(offset - 1, 0));
            }
            if end < width {
                v = x.extract(width - 1, end).concat(&v);
            }
            v
        }
        Select => x.eq(BV::from_u64(1, 1)).ite(a[1], a[2]),
        Parity => {
            let mut odd = x.extract(0, 0);
            for bit in 1..8 {
                odd = odd.bvxor(x.extract(bit, bit));
            }
            odd.bvnot()
        }
        UnsignedMulHigh => x
            .zero_ext(width)
            .bvmul(a[1].zero_ext(width))
            .extract(width * 2 - 1, width),
        SignedMulHigh => x
            .sign_ext(width)
            .bvmul(a[1].sign_ext(width))
            .extract(width * 2 - 1, width),
        Divide { signed, .. } | DivideFault { signed } => {
            let w = x.get_size();
            let dividend = x.concat(a[1]);
            let divisor = if *signed {
                a[2].sign_ext(w)
            } else {
                a[2].zero_ext(w)
            };
            let quotient = if *signed {
                dividend.bvsdiv(&divisor)
            } else {
                dividend.bvudiv(&divisor)
            };
            if matches!(op, DivideFault { .. }) {
                let low = quotient.extract(w - 1, 0);
                let extended = if *signed {
                    low.sign_ext(w)
                } else {
                    low.zero_ext(w)
                };
                boolean(Bool::or(&[
                    a[2].eq(BV::from_u64(0, w)),
                    extended.eq(&quotient).not(),
                ]))
            } else if matches!(
                op,
                Divide {
                    remainder: true,
                    ..
                }
            ) {
                (if *signed {
                    dividend.bvsrem(&divisor)
                } else {
                    dividend.bvurem(&divisor)
                })
                .extract(w - 1, 0)
            } else {
                quotient.extract(w - 1, 0)
            }
        }
        _ => return Err(format!("unsupported scalar SMT operation {op:?}")),
    };
    Ok(result)
}

/// Hidden fixed-purpose entry point, intercepted before application startup.
/// No arbitrary executable, formula text or command line is accepted.
pub fn worker_entry() -> bool {
    if std::env::args_os().nth(1).as_deref() != Some(std::ffi::OsStr::new(WORKER_FLAG)) {
        return false;
    }
    use std::io::{Read, Write};
    let mut bytes = Vec::new();
    let result = match std::io::stdin()
        .take((MAX_REQUEST + 1) as u64)
        .read_to_end(&mut bytes)
    {
        Ok(_) if bytes.len() <= MAX_REQUEST => match serde_json::from_slice::<Query>(&bytes) {
            Ok(query) => {
                // This global knob is changed only inside this disposable worker.
                if query.limits.validate().is_ok() {
                    z3::set_global_param("memory_max_size", &query.limits.memory_mb.to_string());
                }
                DirectZ3.query(query, &())
            }
            Err(_) => Outcome::stopped(Status::Error, "invalid solver request"),
        },
        _ => Outcome::stopped(Status::Error, "solver input limit/read failure"),
    };
    if let Ok(output) = serde_json::to_vec(&result) {
        let _ = std::io::stdout().write_all(&output);
    }
    true
}

/// One owned subprocess per query. Deadlines include startup and translation.
pub struct IsolatedZ3;
impl Backend for IsolatedZ3 {
    fn query(&self, mut query: Query, control: &dyn AnalysisControl) -> Outcome {
        if let Err(e) = query.validate() {
            return Outcome::stopped(Status::Error, e);
        }
        if control.is_cancelled() {
            return Outcome::stopped(Status::Cancelled, "cancelled");
        }
        let result = isolated(&query, control);
        result.unwrap_or_else(|e| Outcome::stopped(Status::Error, e))
    }
}
fn isolated(query: &Query, control: &dyn AnalysisControl) -> Result<Outcome, String> {
    use std::{
        io::{Read, Write},
        process::{Command, Stdio},
        sync::mpsc,
        thread,
        time::Duration,
    };
    let bytes = serde_json::to_vec(query).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_REQUEST {
        return Ok(Outcome::stopped(Status::Limit, "serialized formula budget"));
    }
    let mut command = Command::new(std::env::current_exe().map_err(|e| e.to_string())?);
    command
        .arg(WORKER_FLAG)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    let start = Instant::now();
    let mut child = command
        .spawn()
        .map_err(|e| format!("solver worker spawn: {e}"))?;
    #[cfg(windows)]
    let _job = match job::attach(&child, query.limits.memory_mb) {
        Ok(job) => job,
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
    };
    let mut input = child.stdin.take().ok_or("missing worker stdin")?;
    let mut output = child.stdout.take().ok_or("missing worker stdout")?;
    let writer = thread::spawn(move || input.write_all(&bytes));
    let (send, receive) = mpsc::sync_channel(1);
    let reader = thread::spawn(move || {
        let mut data = Vec::new();
        let read = output
            .by_ref()
            .take((MAX_RESPONSE + 1) as u64)
            .read_to_end(&mut data);
        let _ = send.send((read, data));
    });
    let mut stopped = None;
    // Startup allowance is bounded and separate from Z3's own query timeout.
    let deadline = Duration::from_millis(u64::from(query.limits.timeout_ms) + 1500);
    let result = loop {
        if control.is_cancelled() {
            stopped = Some((Status::Cancelled, "solver cancelled"));
            break None;
        }
        if start.elapsed() >= deadline {
            stopped = Some((Status::Timeout, "solver worker wall deadline"));
            break None;
        }
        if let Ok((read, data)) = receive.try_recv() {
            if read.is_err() || data.len() > MAX_RESPONSE {
                stopped = Some((Status::Error, "solver output limit/read failure"));
                break None;
            }
            break Some(
                serde_json::from_slice::<Outcome>(&data)
                    .map_err(|_| "solver worker failed or returned invalid output".to_string()),
            );
        }
        thread::sleep(Duration::from_millis(5));
    };
    // Also terminates a child that emitted output but failed to exit.
    let _ = child.kill();
    let _ = child.wait();
    let _ = writer.join();
    let _ = reader.join();
    if let Some((status, reason)) = stopped {
        return Ok(Outcome::stopped(status, reason));
    }
    result.ok_or("missing solver result")?
}
#[cfg(windows)]
mod job {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::JobObjects::*,
    };
    pub struct Job(HANDLE);
    impl Drop for Job {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    pub fn attach(child: &std::process::Child, memory_mb: u32) -> Result<Job, String> {
        // The worker waits for stdin until after assignment. No formula enters
        // native code before process memory and kill-on-close limits are set.
        unsafe {
            let handle = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if handle.is_null() {
                return Err(format!(
                    "solver job creation: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let job = Job(handle);
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            info.ProcessMemoryLimit = memory_mb as usize * 1024 * 1024;
            if SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &info as *const _ as _,
                std::mem::size_of_val(&info) as u32,
            ) == 0
                || AssignProcessToJobObject(handle, child.as_raw_handle() as _) == 0
            {
                return Err(format!(
                    "solver job assignment: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(job)
        }
    }
}
