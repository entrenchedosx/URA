mod breakpoints;
mod control;
mod events;
mod evidence;
mod hardware;
mod os;
mod symbols;
#[cfg(test)]
mod tests;
mod tracing;
use crate::*;
use os::*;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    ptr::null,
    sync::{Arc, Mutex},
    time::Instant,
};
use windows_sys::Win32::{
    Foundation::*,
    System::{Diagnostics::Debug::*, Threading::*},
};

static NEXT_SESSION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
struct Point {
    uncertain: bool,
    protection: u32,
    view: Breakpoint,
    temporary: Option<(u32, u64)>,
}
#[derive(Clone)]
struct SingleStep {
    thread: u32,
    rearm: Option<u64>,
    stop: bool,
    frozen: Vec<u32>,
}
pub struct WindowsBackend {
    shared: Arc<Mutex<Snapshot>>,
    view: Snapshot,
    started: Instant,
    generation: u64,
    process: Option<Handle>,
    threads: BTreeMap<u32, Handle>,
    points: BTreeMap<u64, Point>,
    hardware: BTreeMap<u64, hardware::Hardware>,
    retired_causes: BTreeMap<u32, (u64, bool)>,
    draining_hardware: bool,
    cleanup_threads: std::collections::BTreeSet<u32>,
    trace: tracing::TraceStore,
    captures: evidence::Captures,
    symbols: BTreeMap<u64, symbols::SymbolFile>,
    control: Option<(u64, u32, Option<u64>, String)>,
    // Windows owns these event handles until exit continuation. We use duplicates.
    event_process: Option<HANDLE>,
    event_threads: BTreeMap<u32, HANDLE>,
    pending: Option<(DEBUG_EVENT, NTSTATUS)>,
    displaced: Option<(u64, u32)>,
    step: Option<SingleStep>,
    owned_traps: std::collections::BTreeSet<u32>,
    image: Option<Image>,
    initial_break: bool,
    system_break: Option<u64>,
    remote_break: Option<u64>,
    break_threads: std::collections::BTreeSet<u32>,
    pause_requested: bool,
    break_at_entry: bool,
    next_breakpoint: u64,
    repair: Option<(u64, u32)>,
    resume_poisoned: bool,
    authorization_failed: bool,
    #[cfg(test)]
    fail_next_continue: bool,
}
impl WindowsBackend {
    pub fn new(shared: Arc<Mutex<Snapshot>>) -> Self {
        let view = shared.lock().unwrap_or_else(|e| e.into_inner()).clone();
        Self {
            view,
            shared,
            started: Instant::now(),
            generation: 0,
            process: None,
            threads: BTreeMap::new(),
            points: BTreeMap::new(),
            hardware: BTreeMap::new(),
            retired_causes: BTreeMap::new(),
            draining_hardware: false,
            cleanup_threads: Default::default(),
            trace: Default::default(),
            captures: Default::default(),
            symbols: Default::default(),
            control: None,
            event_process: None,
            event_threads: BTreeMap::new(),
            pending: None,
            displaced: None,
            step: None,
            owned_traps: Default::default(),
            image: None,
            initial_break: true,
            system_break: None,
            remote_break: None,
            break_threads: Default::default(),
            pause_requested: false,
            break_at_entry: false,
            next_breakpoint: 1,
            repair: None,
            resume_poisoned: false,
            authorization_failed: false,
            #[cfg(test)]
            fail_next_continue: false,
        }
    }
    fn publish(&mut self) {
        self.view.breakpoints = self
            .points
            .values()
            .map(|p| p.view.clone())
            .chain(self.hardware.values().map(|h| h.view.clone()))
            .collect();
        self.trace.expire();
        self.view.trace = self.trace.summary();
        self.view.trace["pendingInstructionCleanup"] =
            json!(!self.trace.active && !self.owned_traps.is_empty());
        *self.shared.lock().unwrap_or_else(|e| e.into_inner()) = self.view.clone();
    }
    fn event(&mut self, thread: u32, kind: &str, message: impl Into<String>) {
        let sequence = self.view.events.last().map_or(1, |e| e.sequence + 1);
        if self.view.events.len() == MAX_EVENTS {
            self.view.events.remove(0);
            self.view.events_dropped += 1;
        }
        let message = message.into();
        self.trace_record(
            thread,
            kind,
            None,
            json!({"message":message.chars().take(2048).collect::<String>()}),
        );
        self.view.events.push(Event {
            sequence,
            elapsed_micros: self.started.elapsed().as_micros().min(u64::MAX as u128) as u64,
            thread,
            kind: kind.into(),
            message,
        });
    }
    fn process(&self) -> Result<HANDLE> {
        self.process
            .as_ref()
            .map(|h| h.0)
            .ok_or_else(|| DebugError::new("state", "no live process"))
    }
    fn paused(&self) -> Result<()> {
        if self.view.state != State::Paused || self.pending.is_none() {
            Err(DebugError::new(
                "state",
                "operation requires an outstanding paused debug event",
            ))
        } else {
            Ok(())
        }
    }
    fn thread(&self, tid: Option<u32>) -> Result<(u32, HANDLE)> {
        self.paused()?;
        let tid = tid
            .or(self.view.selected_thread)
            .ok_or_else(|| DebugError::new("thread", "select a thread"))?;
        self.threads
            .get(&tid)
            .map(|h| (tid, h.0))
            .ok_or_else(|| DebugError::new("thread", "thread is not live in this session"))
    }
    fn begin(
        &mut self,
        attached: bool,
        path: &std::path::Path,
        expected: Option<&str>,
    ) -> Result<()> {
        if self.view.state.active() {
            return Err(DebugError::new(
                "state",
                "detach or terminate the current session first",
            ));
        }
        let verified = image(path)?;
        if expected.is_some_and(|expected| expected != verified.hash) {
            return Err(DebugError::new(
                "permission",
                "locked executable hash differs from the authorized target identity",
            ));
        }
        self.image = Some(verified);
        self.generation = NEXT_SESSION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.view = Snapshot {
            schema_version: 1,
            session: Some(format!(
                "debug-{}-{}-{:x}",
                std::process::id(),
                self.generation,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            )),
            state: if attached {
                State::Attaching
            } else {
                State::Launching
            },
            executable: Some(self.image.as_ref().unwrap().path.display().to_string()),
            attached,
            ..Default::default()
        };
        self.started = Instant::now();
        self.initial_break = true;
        self.system_break = None;
        self.remote_break = None;
        self.break_threads.clear();
        self.pause_requested = false;
        self.next_breakpoint = 1;
        self.points.clear();
        self.hardware.clear();
        self.retired_causes.clear();
        self.draining_hardware = false;
        self.cleanup_threads.clear();
        self.trace = Default::default();
        self.captures = Default::default();
        self.symbols.clear();
        self.control = None;
        self.threads.clear();
        self.displaced = None;
        self.step = None;
        self.owned_traps.clear();
        self.pending = None;
        self.repair = None;
        self.resume_poisoned = false;
        self.authorization_failed = false;
        Ok(())
    }
    fn launch(
        &mut self,
        config: LaunchConfig,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<()> {
        unsafe {
            if config.arguments.len() > 256 || config.environment.len() > 64 {
                return Err(DebugError::new(
                    "limit",
                    "at most 256 arguments and 64 environment overrides",
                ));
            }
            self.begin(false, &config.executable, config.expected_sha256.as_deref())?;
            self.break_at_entry = config.break_at_entry;
            let image = self.image.as_ref().unwrap();
            let application = wide(&image.path)?;
            let command = std::iter::once(image.path.to_string_lossy().into_owned())
                .chain(config.arguments)
                .map(|v| quote(&v))
                .collect::<Vec<_>>()
                .join(" ");
            let mut command = wide(command)?;
            if command.len() > 32767 {
                return Err(DebugError::new(
                    "limit",
                    "Windows command line exceeds 32767 UTF-16 units",
                ));
            }
            let directory = config.working_directory.as_ref().map(wide).transpose()?;
            let environment = environment(config.environment)?;
            let startup = STARTUPINFOW {
                cb: std::mem::size_of::<STARTUPINFOW>() as u32,
                ..Default::default()
            };
            let mut info = PROCESS_INFORMATION::default();
            cancel_check(cancelled)?;
            check(
                CreateProcessW(
                    application.as_ptr(),
                    command.as_mut_ptr(),
                    null(),
                    null(),
                    0,
                    DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                    environment.as_ref().map_or(null(), |v| v.as_ptr().cast()),
                    directory.as_ref().map_or(null(), |v| v.as_ptr()),
                    &startup,
                    &mut info,
                ),
                "CreateProcessW",
            )?;
            let process = Handle::new(info.hProcess)?;
            let _thread = Handle::new(info.hThread)?;
            self.view.pid = Some(info.dwProcessId);
            self.process = Some(process);
            check(DebugSetProcessKillOnExit(0), "DebugSetProcessKillOnExit")?;
            architecture(self.process()?)?;
            self.event(
                info.dwThreadId,
                "launch",
                "created explicitly selected target; waiting for initial debug events",
            );
            Ok(())
        }
    }
    fn attach(
        &mut self,
        pid: u32,
        path: std::path::PathBuf,
        expected: Option<&str>,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<()> {
        unsafe {
            if pid == 0 || pid == 4 || pid == GetCurrentProcessId() {
                return Err(DebugError::new(
                    "permission",
                    "invalid/self/system process attachment rejected",
                ));
            }
            if self.view.state.active() {
                return Err(DebugError::new("state", "current session is active"));
            }
            let process = Handle::new(OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                0,
                pid,
            ))?;
            architecture(process.0)?;
            let actual = process_path(process.0)?
                .canonicalize()
                .map_err(|e| DebugError::new("path", e.to_string()))?;
            let requested = path
                .canonicalize()
                .map_err(|e| DebugError::new("path", e.to_string()))?;
            if actual != requested {
                return Err(DebugError::new(
                    "permission",
                    "PID executable does not match the explicitly allowed image",
                ));
            }
            self.begin(true, &requested, expected)?;
            self.break_at_entry = false;
            cancel_check(cancelled)?;
            check(DebugActiveProcess(pid), "DebugActiveProcess")?;
            self.view.pid = Some(pid);
            self.process = Some(process);
            check(DebugSetProcessKillOnExit(0), "DebugSetProcessKillOnExit")?;
            self.event(
                0,
                "attach",
                "attached to explicitly selected PID; waiting for Windows initial breakpoint",
            );
            Ok(())
        }
    }
    fn continue_pending(&mut self, status: NTSTATUS) -> Result<()> {
        #[cfg(test)]
        if self.fail_next_continue {
            self.fail_next_continue = false;
            return Err(DebugError::new(
                "injected",
                "ContinueDebugEvent failure injection",
            ));
        }
        unsafe {
            let (event, _) = self
                .pending
                .as_ref()
                .ok_or_else(|| DebugError::new("state", "no outstanding debug event"))?;
            check(
                ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status),
                "ContinueDebugEvent",
            )?;
            self.pending = None;
            Ok(())
        }
    }
    fn pause_event(&mut self, reason: &str, status: NTSTATUS) -> Result<()> {
        for m in &mut self.view.modules {
            let refreshed = module(
                self.process.as_ref().unwrap().0,
                ura_core::parse_address(&m.base).unwrap_or(0),
                m.path.clone(),
            );
            m.size = refreshed.size;
        }
        let (event, default) = self.pending.as_mut().unwrap();
        *default = status;
        let tid = event.dwThreadId;
        self.view.state = State::Paused;
        self.trace_record(
            tid,
            "state",
            None,
            json!({"state":"paused","reason":reason}),
        );
        self.view.selected_thread = Some(tid);
        self.view.reason = Some(reason.into());
        if let Some(h) = self.threads.get(&tid) {
            self.view.registers = Some(registers(tid, &context(h.0)?));
        }
        Ok(())
    }
    fn finish_cleanup_thread(&mut self, tid: u32) -> Result<()> {
        if self.owned_traps.contains(&tid) {
            if let Some(thread) = self.threads.get(&tid) {
                let mut c = context(thread.0)?;
                c.0.EFlags &= !0x100;
                c.0.Dr6 &= !(1 << 14);
                set_context(thread.0, &c)?;
            }
            self.owned_traps.remove(&tid);
        }
        self.hardware_finish_disabled(tid)?;
        self.cleanup_threads.remove(&tid);
        Ok(())
    }
    fn detach_paused(&mut self) -> Result<()> {
        unsafe {
            self.paused()?;
            self.trace.finish("detach");
            self.repair_breakpoint()?;
            if let Some(step) = self.step.as_mut() {
                step.rearm = None;
            }
            let addresses = self.points.keys().copied().collect::<Vec<_>>();
            for address in addresses {
                self.remove_point(address)?;
            }
            self.displaced = None;
            self.control = None;
            self.release_step()?;
            self.cleanup_threads = self.hardware_cleanup_threads();
            self.cleanup_threads
                .extend(self.owned_traps.iter().copied());
            let current = self.pending.as_ref().unwrap().0.dwThreadId;
            self.finish_cleanup_thread(current)?;
            for tid in self.cleanup_threads.iter().copied().collect::<Vec<_>>() {
                if let Some(thread) = self.threads.get(&tid) {
                    let mut c = context(thread.0)?;
                    if c.0.EFlags & 0x100 == 0 {
                        c.0.EFlags |= 0x100;
                        self.owned_traps.insert(tid);
                        set_context(thread.0, &c)?;
                    }
                }
            }
            self.draining_hardware = true;
            let deadline = Instant::now() + std::time::Duration::from_secs(3);
            let mut stop_error = None;
            let drained = (|| {
                while (!self.cleanup_threads.is_empty()
                    || self.pause_requested
                    || self.pending.is_none())
                    && self.view.state.active()
                {
                    if Instant::now() >= deadline {
                        return Err(DebugError::new("cleanup",format!("thread handoff is still pending (possibly a blocked instruction); owner retained, retry detach{}", stop_error.as_ref().map_or(String::new(), |e| format!("; final stop: {e}")))));
                    }
                    if let Some((_, status)) = self.pending.as_ref() {
                        let status = *status;
                        self.continue_pending(status)?;
                        self.view.state = State::Running;
                    }
                    if self.cleanup_threads.is_empty()
                        && self.pending.is_none()
                        && !self.pause_requested
                        && stop_error.is_none()
                    {
                        match check(
                            DebugBreakProcess(self.process()?),
                            "DebugBreakProcess cleanup stop",
                        ) {
                            Ok(()) => self.pause_requested = true,
                            // The target can have exited between continuation and
                            // this request. Drain its real exit event before deciding.
                            Err(e) => stop_error = Some(e.message),
                        }
                    }
                    self.poll();
                }
                Ok(())
            })();
            self.draining_hardware = false;
            drained?;
            if !self.view.state.active() {
                return Ok(());
            }
            self.paused()?;
            self.view.state = State::Detaching;
            let status = self.pending.as_ref().unwrap().1;
            self.continue_pending(status)?;
            if let Err(e) = check(
                DebugActiveProcessStop(self.view.pid.unwrap()),
                "DebugActiveProcessStop",
            ) {
                self.view.state = State::Running;
                return Err(e);
            }
            self.close_event_handles();
            self.hardware.clear();
            self.owned_traps.clear();
            self.process = None;
            self.threads.clear();
            self.image = None;
            self.view.state = State::Detached;
            self.view.registers = None;
            self.view.threads.clear();
            self.view.modules.clear();
            self.event(
                0,
                "detached",
                "target left running; debugger-owned bytes restored",
            );
            Ok(())
        }
    }
    fn close_event_handles(&mut self) {
        unsafe {
            if let Some(h) = self.event_process.take() {
                if CloseHandle(h) == 0 {
                    self.event(
                        0,
                        "cleanupError",
                        error("CloseHandle event process").message,
                    );
                }
            }
            for (_, h) in std::mem::take(&mut self.event_threads) {
                if CloseHandle(h) == 0 {
                    self.event(0, "cleanupError", error("CloseHandle event thread").message);
                }
            }
        }
    }
    fn execute(
        &mut self,
        session: Option<&str>,
        command: Command,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<Value> {
        if self.authorization_failed
            && !matches!(
                command,
                Command::Detach | Command::Terminate | Command::Pause
            )
            && (self.view.state.active()
                || !matches!(command, Command::Launch(_) | Command::Attach { .. }))
        {
            return Err(DebugError::new(
                "permission",
                "debug-event image identity failed; only cleanup controls are permitted",
            ));
        }
        if !matches!(command, Command::Launch(_) | Command::Attach { .. })
            && (session.is_none() || session != self.view.session.as_deref())
        {
            return Err(DebugError::new(
                "stale_session",
                "valid current debug session handle required",
            ));
        }
        match command {
            Command::Capabilities => {
                return Ok(
                    json!({"backend":"windows-user-mode","architecture":"x64","hardwareSlotsPerThread":4,"watchSizes":[1,2,4,8],"watchAccess":["write","readWrite"],"conditionalRegisters":true,"stepOut":"validated unwind caller","runTo":true,"trace":["events","instructions"],"snapshotMaxBytes":1048576,"wow64":false,"remote":false}),
                )
            }
            Command::ConfigureBreakpoint(config) => self.configure_point(config)?,
            Command::SetCondition {
                id,
                condition,
                hit_after,
                hit_every,
            } => {
                if hit_after == 0 || hit_every == 0 {
                    return Err(DebugError::new("condition", "hit counts must be positive"));
                }
                if let Some(text) = &condition {
                    Condition::parse(text)?;
                }
                self.paused()?;
                let view = if let Some(h) = self.hardware.get_mut(&id) {
                    &mut h.view
                } else {
                    &mut self
                        .points
                        .values_mut()
                        .find(|p| p.view.id == id)
                        .ok_or_else(|| DebugError::new("breakpoint", "unknown point"))?
                        .view
                };
                view.condition = condition;
                view.hit_after = hit_after;
                view.hit_every = hit_every;
            }
            Command::StepOut => self.step_out()?,
            Command::RunTo { address } => self.run_to(address, None, "runTo")?,
            Command::Trace(action) => return self.trace_action(action),
            Command::Regions { address, limit } => {
                self.paused()?;
                return evidence::regions(self.process()?, address, limit);
            }
            Command::Capture(action) => return self.capture_action(action),
            Command::Symbols(action) => return self.symbol_action(action),
            Command::Launch(config) => self.launch(config, cancelled)?,
            Command::Attach {
                pid,
                executable,
                expected_sha256,
            } => self.attach(pid, executable, expected_sha256.as_deref(), cancelled)?,
            Command::Continue { pass_exception } => self.resume(None, pass_exception)?,
            Command::Step { over } => self.resume(Some(over), true)?,
            Command::Pause => {
                if self.remote_break.is_none() {
                    return Err(DebugError::new(
                        "unsupported",
                        "Windows break-in helper identity is unavailable; pause was not issued",
                    ));
                }
                if !matches!(self.view.state, State::Running | State::Stepping) {
                    return Err(DebugError::new(
                        "state",
                        "pause requires running or stepping state",
                    ));
                }
                unsafe {
                    check(DebugBreakProcess(self.process()?), "DebugBreakProcess")?;
                }
                self.pause_requested = true;
            }
            Command::Detach => {
                if self.view.state == State::Paused {
                    self.detach_paused()?;
                } else {
                    return Err(DebugError::new(
                        "state",
                        "pause and wait for the debug event before clean detach",
                    ));
                }
            }
            Command::Terminate => {
                unsafe {
                    check(
                        TerminateProcess(self.process()?, 0x555241),
                        "TerminateProcess",
                    )?;
                }
                self.view.state = State::Terminating;
                if let Some((_, status)) = &self.pending {
                    self.continue_pending(*status)?;
                }
            }
            Command::Registers { thread } => {
                let (tid, h) = self.thread(thread)?;
                let regs = registers(tid, &context(h)?);
                self.view.selected_thread = Some(tid);
                self.view.registers = Some(regs.clone());
                return Ok(json!(regs));
            }
            Command::Memory { address, length } => {
                self.paused()?;
                return memory(self.process()?, address, length);
            }
            Command::Stack { thread, limit } => {
                let (tid, h) = self.thread(thread)?;
                let mut result = stack(self.process()?, h, tid, &self.view.modules, limit)?;
                if let (Some(image), Some(main), Some(frames)) = (
                    &self.image,
                    self.view.modules.iter().find(|m| m.sha256.is_some()),
                    result["frames"].as_array_mut(),
                ) {
                    let base = ura_core::parse_address(&main.base).unwrap_or(0);
                    for frame in frames {
                        if let Some(rva) = frame["instructionPointer"]
                            .as_str()
                            .and_then(|s| ura_core::parse_address(s).ok())
                            .and_then(|ip| ip.checked_sub(base))
                        {
                            if let Some(name) = image.exports.get(&rva) {
                                frame["symbol"] = json!(name);
                            }
                        }
                    }
                }
                self.symbolize_stack(&mut result);
                return Ok(result);
            }
            Command::Disassembly { address, count } => {
                self.paused()?;
                if count == 0 || count > 128 {
                    return Err(DebugError::new(
                        "limit",
                        "runtime instruction count must be 1..=128",
                    ));
                }
                let response = memory(self.process()?, address, (count * 15).min(4096))?;
                let bytes = response["bytes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_u64().unwrap() as u8)
                    .collect::<Vec<_>>();
                use ura_core::disasm::InstructionDecoder;
                let page = ura_core::disasm::X86Decoder
                    .decode(&bytes, address, 64, None, count)
                    .map_err(|e| DebugError::new("decode", e.to_string()))?;
                return Ok(
                    json!({"addressSpace":"runtime","instructions":page.instructions,"read":response,"note":"actual process bytes include armed INT3 breakpoints"}),
                );
            }
            Command::Breakpoint {
                action,
                address,
                id,
            } => {
                self.paused()?;
                if action == "set" {
                    self.add_point(
                        address.ok_or_else(|| DebugError::new("argument", "address required"))?,
                        None,
                        "user",
                    )?;
                } else if let Some(id) = id.filter(|id| self.hardware.contains_key(id)) {
                    self.hardware_action(id, &action)?;
                } else {
                    let address = self
                        .points
                        .iter()
                        .find(|(_, p)| Some(p.view.id) == id)
                        .map(|(&a, _)| a)
                        .ok_or_else(|| DebugError::new("breakpoint", "unknown breakpoint ID"))?;
                    match action.as_str() {
                        "remove" => self.remove_point(address)?,
                        "disable" => {
                            self.arm(address, false)?;
                            self.points.get_mut(&address).unwrap().view.enabled = false;
                        }
                        "enable" => {
                            if self.displaced.is_some_and(|v| v.0 == address) {
                                return Err(DebugError::new(
                                    "state",
                                    "cannot arm the displaced instruction before executing it",
                                ));
                            }
                            self.arm(address, true)?;
                            self.points.get_mut(&address).unwrap().view.enabled = true;
                        }
                        _ => {
                            return Err(DebugError::new(
                                "argument",
                                "breakpoint action is set,remove,enable,disable",
                            ))
                        }
                    }
                }
            }
        }
        self.publish();
        Ok(json!(self.view))
    }
}
impl Backend for WindowsBackend {
    fn stable(&self) -> bool {
        (self.pending.is_some() || !self.view.state.active()) && !self.trace.active
    }
    fn command(
        &mut self,
        session: Option<&str>,
        command: Command,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<Value> {
        let starting = matches!(command, Command::Launch(_) | Command::Attach { .. });
        let result = self.execute(session, command, cancelled);
        if let Err(e) = &result {
            self.event(0, "error", e.message.clone());
            if starting && !self.view.pid.is_some_and(|_| self.process.is_some()) {
                self.view.state = State::Failed;
                self.image = None;
            }
        }
        self.publish();
        result
    }
    fn poll(&mut self) {
        let was_tracing = self.trace.active;
        self.trace.expire();
        if was_tracing && !self.trace.active {
            self.publish();
        }
        unsafe {
            if self.trace.inflight
                && !self.trace.active
                && self.pending.is_none()
                && !self.pause_requested
                && self.view.state.active()
            {
                if let Err(e) = check(
                    DebugBreakProcess(self.process().unwrap()),
                    "DebugBreakProcess to stop tracing",
                ) {
                    self.event(0, "traceStopError", e.message);
                } else {
                    self.pause_requested = true;
                }
            }
            if self.pending.is_some() && self.trace.active {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            if !self.view.state.active() || self.pending.is_some() || self.process.is_none() {
                return;
            }
            let mut event = DEBUG_EVENT::default();
            if WaitForDebugEventEx(&mut event, 20) != 0 {
                if let Err(e) = self.on_event(event) {
                    let fatal = e.code == "identity" || e.code == "permission";
                    self.event(event.dwThreadId, "error", e.message);
                    if self.pending.is_some() {
                        self.view.state = State::Paused;
                        self.view.reason = Some(
                            if fatal {
                                "authorizationFailed"
                            } else {
                                "backendError"
                            }
                            .into(),
                        );
                        if fatal {
                            self.authorization_failed = true;
                            let cleanup = if self.view.attached {
                                self.detach_paused().map(|_| Value::Null)
                            } else {
                                let session = self.view.session.clone();
                                self.execute(
                                    session.as_deref(),
                                    Command::Terminate,
                                    &std::sync::atomic::AtomicBool::new(false),
                                )
                            };
                            if let Err(e) = cleanup {
                                self.event(0, "cleanupError", e.message);
                            }
                        }
                    }
                }
                self.publish();
            } else {
                let e = GetLastError();
                if e != ERROR_SEM_TIMEOUT && e != ERROR_TIMEOUT {
                    self.event(0, "error", format!("WaitForDebugEventEx failed: {e}"));
                    self.publish();
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
            }
        }
    }
    fn shutdown(&mut self) {
        unsafe {
            if !self.view.state.active() {
                return;
            }
            // Request a real break, drain events on their owning thread, restore, detach.
            if self.pending.is_none() && self.process.is_some() {
                if !self.initial_break
                    && !self.pause_requested
                    && self.remote_break.is_some()
                    && DebugBreakProcess(self.process.as_ref().unwrap().0) != 0
                {
                    self.pause_requested = true;
                }
                let until = Instant::now() + std::time::Duration::from_secs(3);
                while self.pending.is_none() && self.view.state.active() && Instant::now() < until {
                    self.poll();
                }
            }
            if self.pending.is_some() {
                self.view.state = State::Paused;
                if let Err(e) = self.detach_paused() {
                    self.event(0, "cleanupError", e.message);
                }
            }
            if self.view.state.active() && !self.view.attached {
                // A launched target may be terminated on unrecoverable cleanup; attached processes never are.
                if let Some(p) = &self.process {
                    if TerminateProcess(p.0, 0x555241) != 0 {
                        if let Some((_, status)) = &self.pending {
                            let _ = self.continue_pending(*status);
                        }
                        self.view.state = State::Terminating;
                        let until = Instant::now() + std::time::Duration::from_secs(2);
                        while self.view.state.active() && Instant::now() < until {
                            self.poll();
                        }
                    }
                }
            }
            self.publish();
            // Never abandon an attached process with owned bytes/TF/suspend counts.
            // Keep the event owner alive for retry instead of allowing implicit OS detach.
            while self.view.attached && self.view.state.active() {
                self.view.reason = Some("cleanupPending".into());
                self.event(
                    0,
                    "cleanupPending",
                    "attached target cleanup is incomplete; event owner retained for retry",
                );
                self.publish();
                std::thread::sleep(std::time::Duration::from_millis(250));
                if self.pending.is_some() {
                    self.view.state = State::Paused;
                    let _ = self.detach_paused();
                } else {
                    if let Some(p) = &self.process {
                        if !self.initial_break
                            && !self.pause_requested
                            && self.remote_break.is_some()
                            && DebugBreakProcess(p.0) != 0
                        {
                            self.pause_requested = true;
                        }
                    }
                    self.poll();
                }
            }
        }
    }
}
fn cancel_check(cancelled: &std::sync::atomic::AtomicBool) -> Result<()> {
    if cancelled.load(std::sync::atomic::Ordering::Acquire) {
        Err(DebugError::new(
            "cancelled",
            "debug operation cancelled before OS launch/attach",
        ))
    } else {
        Ok(())
    }
}
fn environment(overrides: BTreeMap<String, String>) -> Result<Option<Vec<u16>>> {
    if overrides.is_empty() {
        return Ok(None);
    }
    let mut env = BTreeMap::new();
    for (k, v) in std::env::vars_os() {
        let k = k.into_string().map_err(|_| {
            DebugError::new(
                "environment",
                "non-Unicode inherited environment cannot be overridden",
            )
        })?;
        let v = v.into_string().map_err(|_| {
            DebugError::new(
                "environment",
                "non-Unicode inherited environment cannot be overridden",
            )
        })?;
        env.insert(k.to_uppercase(), v);
    }
    for (k, v) in overrides {
        if k.is_empty() || k.contains(['=', '\0']) || v.contains('\0') {
            return Err(DebugError::new(
                "environment",
                "invalid environment override",
            ));
        }
        env.insert(k.to_uppercase(), v);
    }
    let mut block = Vec::new();
    for (k, v) in env {
        block.extend(wide(format!("{k}={v}"))?);
    }
    block.push(0);
    if block.len() > 32767 {
        return Err(DebugError::new(
            "limit",
            "environment exceeds 32767 UTF-16 units",
        ));
    }
    Ok(Some(block))
}

impl Drop for WindowsBackend {
    fn drop(&mut self) {
        self.shutdown();
    }
}
