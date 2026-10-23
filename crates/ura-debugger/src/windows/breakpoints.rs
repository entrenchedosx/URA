use super::*;
impl WindowsBackend {
    pub(super) fn add_point(
        &mut self,
        address: u64,
        temporary: Option<(u32, u64)>,
        owner: &str,
    ) -> Result<u64> {
        if self.points.len() >= MAX_BREAKPOINTS {
            return Err(DebugError::new("limit", "breakpoint limit reached"));
        }
        if self.points.contains_key(&address) {
            return Err(DebugError::new(
                "conflict",
                "breakpoint address already owned; remove it before this operation",
            ));
        }
        let region = memory(self.process()?, address, 1)?;
        let protection = region["region"]["protection"]
            .as_u64()
            .ok_or_else(|| DebugError::new("memory", "breakpoint region unavailable"))?
            as u32;
        let original = read(self.process()?, address, 1)?[0];
        if original == 0xcc {
            return Err(DebugError::new(
                "conflict",
                "existing INT3 belongs to the application or another owner",
            ));
        }
        let id = self.next_breakpoint;
        self.next_breakpoint += 1;
        let module = self.view.modules.iter().find(|m| {
            ura_core::parse_address(&m.base).is_ok_and(|b| address >= b && address - b < m.size)
        });
        self.points.insert(
            address,
            Point {
                uncertain: false,
                protection,
                temporary,
                view: Breakpoint {
                    verification: None,
                    thread_filter: None,
                    kind: BreakpointKind::Software,
                    length: 1,
                    threads: vec![],
                    slots: Default::default(),
                    condition: None,
                    hit_after: 1,
                    hit_every: 1,
                    id,
                    session: self.view.session.clone().unwrap(),
                    address: hex(address),
                    enabled: true,
                    armed: false,
                    original_byte: original,
                    hits: 0,
                    owner: owner.into(),
                    module: module.and_then(|m| m.path.clone()),
                    rva: module.map(|m| hex(address - ura_core::parse_address(&m.base).unwrap())),
                },
            },
        );
        // A removed/restored breakpoint at the currently displaced instruction
        // must wait until that original instruction executes before rearming.
        if !self
            .displaced
            .is_some_and(|(stopped, _)| stopped == address)
        {
            self.arm(address, true)?;
        }
        Ok(id)
    }
    pub(super) fn arm(&mut self, address: u64, armed: bool) -> Result<()> {
        let p = self
            .points
            .get(&address)
            .ok_or_else(|| DebugError::new("breakpoint", "unknown breakpoint"))?;
        if p.uncertain {
            if armed {
                return Err(DebugError::new("critical","uncertain breakpoint bytes/protection require verified cleanup before execution"));
            }
            repair_byte(self.process()?, address, p.view.original_byte, p.protection)?;
            let p = self.points.get_mut(&address).unwrap();
            p.uncertain = false;
            p.view.armed = false;
            p.view.verification = None;
            return Ok(());
        }
        if p.view.armed == armed {
            return Ok(());
        }
        let result = byte(
            self.process()?,
            address,
            if armed { p.view.original_byte } else { 0xcc },
            if armed { 0xcc } else { p.view.original_byte },
        );
        if let Err(e) = result {
            {
                let p = self.points.get_mut(&address).unwrap();
                p.uncertain = true;
                p.view.verification = Some(e.message.clone());
                self.resume_poisoned = true;
            }
            return Err(e);
        }
        self.points.get_mut(&address).unwrap().view.armed = armed;
        Ok(())
    }
    pub(super) fn remove_point(&mut self, address: u64) -> Result<()> {
        self.arm(address, false)?;
        self.points.remove(&address);
        Ok(())
    }
    pub(super) fn freeze_others(&mut self, thread: u32) -> Result<Vec<u32>> {
        unsafe {
            let mut frozen = Vec::new();
            for (&tid, handle) in &self.threads {
                if tid != thread {
                    if SuspendThread(handle.0) == u32::MAX {
                        let failure = error("SuspendThread for displaced instruction");
                        let mut remaining = Vec::new();
                        for &id in &frozen {
                            if let Some(h) = self.threads.get(&id) {
                                if ResumeThread(h.0) == u32::MAX {
                                    remaining.push(id);
                                }
                            }
                        }
                        if !remaining.is_empty() {
                            self.step = Some(SingleStep {
                                thread,
                                rearm: None,
                                stop: false,
                                frozen: remaining,
                            });
                        }
                        return Err(failure);
                    }
                    frozen.push(tid);
                }
            }
            Ok(frozen)
        }
    }
    pub(super) fn release_step(&mut self) -> Result<Option<SingleStep>> {
        unsafe {
            let Some(mut step) = self.step.clone() else {
                return Ok(None);
            };
            let mut failure = None;
            if let Some(address) = step.rearm {
                if self.points.get(&address).is_some_and(|p| p.view.enabled) {
                    match self.arm(address, true) {
                        Ok(()) => step.rearm = None,
                        Err(e) => failure = Some(e),
                    }
                } else {
                    step.rearm = None;
                }
            }
            let mut remaining = Vec::new();
            for &tid in &step.frozen {
                if let Some(thread) = self.threads.get(&tid) {
                    if ResumeThread(thread.0) == u32::MAX {
                        failure = Some(error("ResumeThread owned suspend"));
                        remaining.push(tid);
                    }
                }
            }
            step.frozen = remaining;
            if let Some(e) = failure {
                self.step = Some(step);
                return Err(e);
            }
            self.step = self.parked_step.take();
            Ok(Some(step))
        }
    }
    pub(super) fn repair_breakpoint(&mut self) -> Result<()> {
        let Some((address, tid)) = self.repair else {
            return Ok(());
        };
        let h = self
            .threads
            .get(&tid)
            .ok_or_else(|| DebugError::new("repair", "breakpoint thread unavailable"))?
            .0;
        let mut c = context(h)?;
        if c.0.Rip != address && c.0.Rip != address + 1 {
            return Err(DebugError::new(
                "repair",
                "unexpected breakpoint IP; execution remains stopped",
            ));
        }
        self.arm(address, false)?;
        c.0.Rip = address;
        set_context(h, &c)?;
        self.displaced = Some((address, tid));
        self.repair = None;
        Ok(())
    }
    pub(super) fn resume(&mut self, stepping: Option<bool>, pass_exception: bool) -> Result<()> {
        self.paused()?;
        self.hardware_ready()?;
        if stepping.is_some() && !self.retired_causes.is_empty() {
            return Err(DebugError::new("state","continue or detach to drain queued owned debug causes before starting another step"));
        }
        if !self.cleanup_threads.is_empty() {
            return Err(DebugError::new(
                "cleanup",
                "detach cleanup retains thread ownership; retry detach or terminate explicitly",
            ));
        }
        self.repair_breakpoint()?;
        if self.resume_poisoned {
            return Err(DebugError::new(
                "repair",
                "resume rollback incomplete; detach or terminate required",
            ));
        }
        if let Some(step) = &self.step {
            if self.displaced.is_some_and(|(_, tid)| tid != step.thread) {
                if stepping.is_some()
                    || step.rearm.is_some()
                    || !step.frozen.is_empty()
                    || self.parked_step.is_some()
                {
                    return Err(DebugError::new("state",format!("foreign displacement handoff cannot continue safely: step owner={}, event owner={:?}, stepping={}, rearm={:?}, frozen={}, parked={}; retry detach or terminate",step.thread,self.displaced.map(|v|v.1),stepping.is_some(),step.rearm,step.frozen.len(),self.parked_step.is_some())));
                }
                self.parked_step = self.step.take();
            }
        }
        if let Some(step) = &self.step {
            if stepping.is_none()
                && self
                    .pending
                    .as_ref()
                    .is_some_and(|p| p.0.dwThreadId != step.thread)
            {
                let default = self.pending.as_ref().unwrap().1;
                self.continue_pending(if default == DBG_EXCEPTION_NOT_HANDLED && pass_exception {
                    DBG_EXCEPTION_NOT_HANDLED
                } else {
                    DBG_CONTINUE
                })?;
                self.view.state = State::Stepping;
                return Ok(());
            }
            return Err(DebugError::new(
                "state",
                "interrupted step must complete in its owner thread; continue, detach or terminate",
            ));
        }
        let tid = self.pending.as_ref().unwrap().0.dwThreadId;
        let h = self
            .threads
            .get(&tid)
            .ok_or_else(|| DebugError::new("thread", "event thread unavailable"))?
            .0;
        let original = context(h)?;
        let existing = self.points.keys().copied().collect::<Vec<_>>();
        let result = self.resume_inner(stepping, pass_exception);
        if result.is_err() && self.pending.is_some() {
            let mut failures = Vec::new();
            if let Err(e) = set_context(h, &original) {
                failures.push(e.message);
            } else if original.0.EFlags & 0x100 == 0 {
                self.owned_traps.remove(&tid);
            }
            // resume_inner may already have rolled back the event-thread step
            // and restored the parked owner. Never release that other owner.
            if self.step.as_ref().is_some_and(|step| step.thread == tid) {
                if let Some(step) = self.step.as_mut() {
                    step.rearm = None;
                }
                if let Err(e) = self.release_step() {
                    failures.push(e.message);
                }
            }
            let added = self
                .points
                .keys()
                .copied()
                .filter(|a| !existing.contains(a))
                .collect::<Vec<_>>();
            for a in added {
                if let Err(e) = self.remove_point(a) {
                    failures.push(e.message);
                }
            }
            if !failures.is_empty() {
                self.resume_poisoned = true;
                return Err(DebugError::new(
                    "repair",
                    format!("resume rollback incomplete: {}", failures.join("; ")),
                ));
            }
        }
        if self.step.is_none() {
            self.step = self.parked_step.take();
        }
        result
    }
    pub(super) fn resume_inner(
        &mut self,
        stepping: Option<bool>,
        pass_exception: bool,
    ) -> Result<()> {
        self.paused()?;
        self.hardware_ready()?;
        if stepping.is_some() && !self.retired_causes.is_empty() {
            return Err(DebugError::new("state","continue or detach to drain queued owned debug causes before starting another step"));
        }
        if self.step.is_some() {
            return Err(DebugError::new("state","interrupted displaced step must be detached or terminated; unsafe resumption rejected"));
        }
        let event_thread = self.pending.as_ref().unwrap().0.dwThreadId;
        let tid = self.view.selected_thread.unwrap_or(event_thread);
        // Continuing an exception always acts on its event thread; single-step selection must agree.
        if stepping.is_some() && tid != event_thread {
            return Err(DebugError::new(
                "thread",
                "select the stopped event thread before stepping",
            ));
        }
        let handle = self
            .threads
            .get(&event_thread)
            .ok_or_else(|| DebugError::new("thread", "event thread exited"))?
            .0;
        let mut c = context(handle)?;
        let mut step_into = stepping == Some(false);
        if stepping == Some(true) {
            let bytes = read(self.process()?, c.0.Rip, 15)?;
            let mut decoder =
                iced_x86::Decoder::with_ip(64, &bytes, c.0.Rip, iced_x86::DecoderOptions::NONE);
            let instruction = decoder.decode();
            if instruction.is_invalid() {
                return Err(DebugError::new(
                    "instruction",
                    "cannot step invalid instruction",
                ));
            }
            if instruction.flow_control() == iced_x86::FlowControl::Call {
                self.add_point(
                    instruction.next_ip(),
                    Some((event_thread, c.0.Rsp)),
                    "stepOver",
                )?;
            } else if instruction.flow_control() == iced_x86::FlowControl::IndirectCall {
                return Err(DebugError::new(
                    "unsupported",
                    "step-over currently supports direct calls only",
                ));
            } else {
                step_into = true;
            }
        }
        if self.displaced.is_some_and(|(_, tid)| tid != event_thread) {
            return Err(DebugError::new(
                "state",
                "displaced instruction belongs to another thread; detach or terminate required",
            ));
        }
        let rearm = self.displaced.map(|v| v.0);
        if step_into || rearm.is_some() {
            if c.0.EFlags & 0x100 != 0 {
                return Err(DebugError::new(
                    "context",
                    "target already owns trap flag; stepping refused",
                ));
            }
            // Other threads must not cross a temporarily restored software BP.
            // Ordinary TF stepping needs no such suspension; freezing a thread
            // that owns a lock needed by this instruction can deadlock the target.
            let frozen = if rearm.is_some() {
                self.freeze_others(event_thread)?
            } else {
                vec![]
            };
            c.0.EFlags |= 0x100;
            self.owned_traps.insert(event_thread);
            if let Err(e) = set_context(handle, &c) {
                self.step = Some(SingleStep {
                    thread: event_thread,
                    rearm: None,
                    stop: false,
                    frozen,
                });
                let _ = self.release_step();
                return Err(e);
            }
            self.step = Some(SingleStep {
                thread: event_thread,
                rearm,
                stop: step_into,
                frozen,
            });
        }
        let default = self.pending.as_ref().unwrap().1;
        let status = if default == DBG_EXCEPTION_NOT_HANDLED && pass_exception {
            DBG_EXCEPTION_NOT_HANDLED
        } else {
            DBG_CONTINUE
        };
        self.continue_pending(status)?;
        self.displaced = None;
        self.view.registers = None;
        self.view.state = if stepping.is_some() {
            State::Stepping
        } else {
            State::Running
        };
        self.view.reason = None;
        Ok(())
    }
}
