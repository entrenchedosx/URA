//! Observed evidence only. Storage bounds apply to serialized payload bytes.
use super::*;
use std::collections::VecDeque;
#[derive(Default)]
pub(super) struct TraceStore {
    config: Option<TraceConfig>,
    pub(super) active: bool,
    started: Option<Instant>,
    entries: VecDeque<(Value, usize)>,
    bytes: usize,
    sequence: u64,
    dropped: u64,
    steps: u64,
    reason: Option<String>,
    thread: Option<u32>,
    previous: BTreeMap<String, String>,
    pub inflight: bool,
}
impl TraceStore {
    pub(super) fn finish(&mut self, reason: &str) {
        if self.active {
            self.stop(reason);
        }
        self.inflight = false;
    }
    fn stop(&mut self, reason: &str) {
        self.active = false;
        self.reason = Some(reason.into());
    }
    pub(super) fn expire(&mut self) {
        if self.active
            && self
                .started
                .zip(self.config.as_ref())
                .is_some_and(|(s, c)| s.elapsed().as_millis() >= c.max_duration_ms as u128)
        {
            self.stop("durationLimit");
        }
    }
    pub(super) fn summary(&self) -> Value {
        json!({"active":self.active,"instructionInFlight":self.inflight,"config":self.config,"retained":self.entries.len(),"serializedBytes":self.bytes,"dropped":self.dropped,"truncated":self.dropped!=0,"steps":self.steps,"stopReason":self.reason,"lateStart":true,"completeExecution":false,"lastSequence":self.sequence})
    }
    fn push(&mut self, mut entry: Value) {
        self.expire();
        if !self.active {
            return;
        }
        self.sequence += 1;
        entry["sequence"] = json!(self.sequence);
        entry["elapsedMicros"] = json!(self
            .started
            .unwrap()
            .elapsed()
            .as_micros()
            .min(u64::MAX as u128) as u64);
        let bytes = serde_json::to_vec(&entry).unwrap().len();
        let config = self.config.as_ref().unwrap();
        if bytes > config.max_bytes {
            self.dropped += 1;
            self.stop("entryByteLimit");
            return;
        }
        while self.entries.len() >= config.max_events || self.bytes + bytes > config.max_bytes {
            let (_, old) = self.entries.pop_front().unwrap();
            self.bytes -= old;
            self.dropped += 1;
        }
        self.bytes += bytes;
        self.entries.push_back((entry, bytes));
    }
}
impl WindowsBackend {
    pub(super) fn trace_record(
        &mut self,
        thread: u32,
        kind: &str,
        address: Option<u64>,
        detail: Value,
    ) {
        let module=address.and_then(|a|self.view.modules.iter().find(|m|ura_core::parse_address(&m.base).is_ok_and(|b|a>=b && a-b<m.size)).map(|m|json!({"base":m.base,"size":m.size,"path":m.path,"sha256":m.sha256,"rva":hex(a-ura_core::parse_address(&m.base).unwrap())})));
        self.trace.push(json!({"session":self.view.session,"pid":self.view.pid,"thread":thread,"kind":kind,"address":address.map(hex),"module":module,"detail":detail}));
    }
    pub(super) fn trace_registers(&mut self, thread: u32, regs: &Registers) {
        let ip = regs
            .values
            .get("rip")
            .and_then(|v| ura_core::parse_address(v).ok());
        let mut changed = BTreeMap::new();
        if self.trace.config.as_ref().is_some_and(|c| c.registers) {
            for (name, value) in &regs.values {
                if self.trace.previous.get(name) != Some(value) {
                    changed.insert(name.clone(), value.clone());
                }
            }
            self.trace.previous = regs.values.clone();
        }
        self.trace_record(thread,"instruction",ip,json!({"changedRegisters":changed,"observation":"paused instruction pointer; no memory-write inference"}));
    }
    pub(super) fn stop_instruction_trace(&mut self, reason: &str) {
        if self
            .trace
            .config
            .as_ref()
            .is_some_and(|c| c.mode == TraceMode::Instructions)
        {
            if self.trace.active {
                self.trace.stop(reason);
            }
            self.trace.inflight = false;
        }
    }
    pub(super) fn trace_next(&mut self) -> Result<()> {
        self.trace.inflight = true;
        if let Err(e) = self.resume(Some(false), true) {
            self.trace.stop("stepError");
            self.trace.inflight = false;
            return Err(e);
        }
        Ok(())
    }
    pub(super) fn trace_instruction_stop(&mut self, tid: u32, regs: &Registers) -> Result<bool> {
        if !self.trace.inflight {
            return Ok(false);
        }
        self.trace.inflight = false;
        self.trace.steps += 1;
        self.trace_registers(tid, regs);
        self.trace.expire();
        if self
            .trace
            .config
            .as_ref()
            .is_some_and(|c| self.trace.steps >= c.max_steps)
        {
            self.trace.stop("stepLimit");
        }
        self.pause_event("trace", DBG_CONTINUE)?;
        if self.trace.active {
            if let Err(e) = self.trace_next() {
                self.event(tid, "traceError", e.message);
            }
        }
        Ok(true)
    }
    pub(super) fn trace_action(&mut self, action: TraceAction) -> Result<Value> {
        self.trace.expire();
        match action {
            TraceAction::Start(config) => {
                self.paused()?;
                config.validate()?;
                if config.mode == TraceMode::Instructions && self.remote_break.is_none() {
                    return Err(DebugError::new("unsupported","instruction tracing requires a verified break-in helper for bounded interruption"));
                }
                if self.trace.active || self.trace.inflight {
                    return Err(DebugError::new(
                        "state",
                        "stop the active trace before starting another",
                    ));
                }
                self.trace = TraceStore {
                    active: true,
                    started: Some(Instant::now()),
                    thread: self.view.selected_thread,
                    config: Some(config.clone()),
                    ..Default::default()
                };
                self.trace_record(
                    self.view.selected_thread.unwrap(),
                    "traceStarted",
                    None,
                    json!({"coverage":"observations after explicit start only"}),
                );
                if config.mode == TraceMode::Instructions {
                    let tid = self.pending.as_ref().unwrap().0.dwThreadId;
                    if self.trace.thread != Some(tid) {
                        self.trace.stop("threadMismatch");
                        return Err(DebugError::new(
                            "thread",
                            "instruction tracing requires the stopped event thread",
                        ));
                    }
                    let regs = registers(tid, &context(self.threads[&tid].0)?);
                    self.trace_registers(tid, &regs);
                    if self.trace.active {
                        self.trace_next()?;
                    }
                }
            }
            TraceAction::Stop => self.trace.stop("user"),
            TraceAction::Clear => {
                if self.trace.active || self.trace.inflight {
                    return Err(DebugError::new(
                        "state",
                        "stop and wait for an instruction trace before clearing",
                    ));
                }
                self.trace = TraceStore::default();
            }
            TraceAction::Read { after, limit } => {
                if limit == 0 || limit > 512 {
                    return Err(DebugError::new("limit", "trace page limit1..512"));
                }
                let events = self
                    .trace
                    .entries
                    .iter()
                    .filter(|(v, _)| v["sequence"].as_u64().unwrap() > after)
                    .take(limit)
                    .map(|(v, _)| v.clone())
                    .collect::<Vec<_>>();
                return Ok(
                    json!({"schemaVersion":1,"summary":self.trace.summary(),"events":events}),
                );
            }
            TraceAction::Export => {
                return Ok(
                    json!({"schemaVersion":1,"format":"ura-observed-trace","session":self.view.session,"pid":self.view.pid,"summary":self.trace.summary(),"events":self.trace.entries.iter().map(|(v,_)|v.clone()).collect::<Vec<_>>()}),
                );
            }
        }
        Ok(self.trace.summary())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ring_enforces_count_bytes_order_and_reports_loss() {
        let mut store = TraceStore {
            config: Some(TraceConfig {
                max_events: 2,
                max_bytes: 1024,
                ..Default::default()
            }),
            active: true,
            started: Some(Instant::now()),
            ..Default::default()
        };
        for n in 0..10 {
            store.push(json!({"n":n}));
        }
        assert_eq!(store.entries.len(), 2);
        assert_eq!(store.dropped, 8);
        assert_eq!(store.entries[0].0["sequence"], 9);
        assert!(store.bytes <= 1024);
        store.push(json!({"tooLarge":"x".repeat(2048)}));
        assert!(!store.active);
        assert_eq!(store.reason.as_deref(), Some("entryByteLimit"));
    }
}
