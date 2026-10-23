//! Per-thread DR slot ownership. Never replace unowned enable/control fields.
use super::*;
#[derive(Clone)]
pub(super) struct Binding {
    slot: u8,
    address: u64,
    control: u64,
}
pub(super) struct Hardware {
    pub view: Breakpoint,
    pub thread: Option<u32>,
    bindings: BTreeMap<u32, Binding>,
    pub remove_requested: bool,
}
fn address(c: &Context, slot: u8) -> u64 {
    match slot {
        0 => c.0.Dr0,
        1 => c.0.Dr1,
        2 => c.0.Dr2,
        _ => c.0.Dr3,
    }
}
fn put_address(c: &mut Context, slot: u8, value: u64) {
    match slot {
        0 => c.0.Dr0 = value,
        1 => c.0.Dr1 = value,
        2 => c.0.Dr2 = value,
        _ => c.0.Dr3 = value,
    }
}
fn mask(slot: u8) -> u64 {
    (3u64 << (slot * 2)) | (15u64 << (16 + slot * 4))
}
fn control(kind: BreakpointKind, length: u8, slot: u8) -> u64 {
    let rw = match kind {
        BreakpointKind::HardwareExecute => 0,
        BreakpointKind::Write => 1,
        _ => 3,
    };
    let len = match length {
        1 => 0,
        2 => 1,
        4 => 3,
        8 => 2,
        _ => unreachable!(),
    };
    (1u64 << (slot * 2)) | ((rw | (len << 2)) << (16 + slot * 4))
}
pub(super) fn matches_condition(point: &mut Breakpoint, regs: &Registers) -> Result<bool> {
    point.hits = point.hits.saturating_add(1);
    if point.hits < point.hit_after || (point.hits - point.hit_after) % point.hit_every != 0 {
        return Ok(false);
    }
    point
        .condition
        .as_deref()
        .map(Condition::parse)
        .transpose()?
        .map_or(Ok(true), |c| c.evaluate(regs))
}
impl WindowsBackend {
    pub(super) fn validate_config(&self, c: &BreakpointConfig) -> Result<()> {
        if c.hit_after == 0 || c.hit_every == 0 {
            return Err(DebugError::new(
                "condition",
                "hitAfter/hitEvery must be positive; hit counts are per session",
            ));
        }
        if let Some(condition) = &c.condition {
            Condition::parse(condition)?;
        }
        if let Some(thread) = c.thread {
            if !self.threads.contains_key(&thread) {
                return Err(DebugError::new(
                    "thread",
                    "requested breakpoint thread is not live",
                ));
            }
        }
        if c.kind == BreakpointKind::Software {
            if c.length != 1 || c.thread.is_some() {
                return Err(DebugError::new("unsupported","software points use length1 and all threads; use a register condition for filtering"));
            }
        } else if ![1, 2, 4, 8].contains(&c.length)
            || c.address % c.length as u64 != 0
            || (c.kind == BreakpointKind::HardwareExecute && c.length != 1)
            || c.address.checked_add(c.length as u64).is_none()
        {
            return Err(DebugError::new("alignment","hardware execution length is1; data lengths1/2/4/8 require natural alignment and no overflow"));
        }
        Ok(())
    }
    pub(super) fn configure_point(&mut self, config: BreakpointConfig) -> Result<()> {
        self.paused()?;
        self.validate_config(&config)?;
        if self.points.len() + self.hardware.len() >= MAX_BREAKPOINTS {
            return Err(DebugError::new("limit", "breakpoint limit reached"));
        }
        if config.kind == BreakpointKind::Software {
            self.add_point(config.address, None, "user")?;
            let point = &mut self.points.get_mut(&config.address).unwrap().view;
            point.condition = config.condition;
            point.hit_after = config.hit_after;
            point.hit_every = config.hit_every;
            return Ok(());
        }
        if self.hardware.values().any(|h| {
            h.view.address == hex(config.address)
                && (h.thread.is_none() || config.thread.is_none() || h.thread == config.thread)
        }) {
            return Err(DebugError::new(
                "conflict",
                "overlapping hardware address/thread ownership",
            ));
        }
        let id = self.next_breakpoint;
        self.next_breakpoint += 1;
        let module = self.view.modules.iter().find(|m| {
            ura_core::parse_address(&m.base)
                .is_ok_and(|b| config.address >= b && config.address - b < m.size)
        });
        let view = Breakpoint {
            verification: None,
            thread_filter: config.thread,
            id,
            session: self.view.session.clone().unwrap(),
            address: hex(config.address),
            enabled: true,
            armed: false,
            original_byte: 0,
            hits: 0,
            owner: "user".into(),
            module: module.and_then(|m| m.path.clone()),
            rva: module.map(|m| hex(config.address - ura_core::parse_address(&m.base).unwrap())),
            kind: config.kind,
            length: config.length,
            threads: vec![],
            slots: Default::default(),
            condition: config.condition,
            hit_after: config.hit_after,
            hit_every: config.hit_every,
        };
        self.hardware.insert(
            id,
            Hardware {
                view,
                thread: config.thread,
                bindings: BTreeMap::new(),
                remove_requested: false,
            },
        );
        if let Err(e) = self.enable_hardware(id) {
            if let Err(cleanup) = self.restore_hardware(id) {
                self.resume_poisoned = true;
                return Err(DebugError::new(
                    "critical",
                    format!("{e}; hardware rollback retained: {cleanup}"),
                ));
            }
            self.hardware.remove(&id);
            return Err(e);
        }
        Ok(())
    }
    fn bind_hardware(&mut self, id: u64, tid: u32) -> Result<()> {
        let point = &self.hardware[&id];
        if point.bindings.contains_key(&tid) {
            return Ok(());
        }
        let thread = self
            .threads
            .get(&tid)
            .ok_or_else(|| DebugError::new("thread", "hardware thread exited"))?
            .0;
        let mut c = context(thread)?;
        if c.0.Dr7 & (1 << 13) != 0 {
            return Err(DebugError::new(
                "conflict",
                "target owns debug-register general-detect state",
            ));
        }
        let retired = self.retired_causes.get(&tid).map_or(0, |r| r.0);
        let slot = (0..4u8)
            .find(|slot| {
                c.0.Dr7 & (3u64 << (slot * 2)) == 0 && (c.0.Dr6 | retired) & (1u64 << slot) == 0
            })
            .ok_or_else(|| {
                DebugError::new(
                    "hardware_slots",
                    "all four hardware slots are occupied in this thread",
                )
            })?;
        let binding = Binding {
            slot,
            address: address(&c, slot),
            control: c.0.Dr7 & mask(slot),
        };
        let target = ura_core::parse_address(&point.view.address).unwrap();
        let requested = control(point.view.kind, point.view.length, slot);
        put_address(&mut c, slot, target);
        c.0.Dr7 = (c.0.Dr7 & !mask(slot)) | requested;
        set_context(thread, &c)?;
        let point = self.hardware.get_mut(&id).unwrap();
        point.bindings.insert(tid, binding);
        point.view.slots.insert(tid, slot);
        point.view.threads = point.bindings.keys().copied().collect();
        Ok(())
    }
    pub(super) fn enable_hardware(&mut self, id: u64) -> Result<()> {
        let point = &self.hardware[&id];
        let tids = point.thread.map_or_else(
            || self.threads.keys().copied().collect::<Vec<_>>(),
            |t| vec![t],
        );
        for tid in tids {
            self.bind_hardware(id, tid)?;
        }
        let point = self.hardware.get_mut(&id).unwrap();
        point.view.enabled = true;
        point.view.armed = true;
        Ok(())
    }
    fn restore_binding(&mut self, id: u64, tid: u32) -> Result<()> {
        let Some(binding) = self.hardware[&id].bindings.get(&tid).cloned() else {
            return Ok(());
        };
        if let Some(thread) = self.threads.get(&tid) {
            let mut c = context(thread.0)?;
            let point = &self.hardware[&id].view;
            if address(&c, binding.slot) != ura_core::parse_address(&point.address).unwrap()
                || c.0.Dr7 & mask(binding.slot) != control(point.kind, point.length, binding.slot)
            {
                return Err(DebugError::new(
                    "conflict",
                    "owned hardware slot changed externally; cleanup retained",
                ));
            }
            put_address(&mut c, binding.slot, binding.address);
            c.0.Dr7 = (c.0.Dr7 & !mask(binding.slot)) | binding.control;
            c.0.Dr6 &= !(1u64 << binding.slot);
            set_context(thread.0, &c)?;
        }
        let point = self.hardware.get_mut(&id).unwrap();
        point.bindings.remove(&tid);
        point.view.slots.remove(&tid);
        point.view.threads = point.bindings.keys().copied().collect();
        Ok(())
    }
    fn refresh_hardware(&mut self, id: u64) {
        let point = self.hardware.get_mut(&id).unwrap();
        point.view.armed = !point.bindings.is_empty();
        point.view.verification=(!point.view.enabled && point.view.armed).then(||"logically disabled; physical slots await their thread's next debug event or detach cleanup".into());
        if point.remove_requested && point.bindings.is_empty() {
            self.hardware.remove(&id);
        }
    }
    // Only for a failed configuration: no target instruction has run since these
    // newly owned slots were installed, so there cannot be an older owned hit.
    pub(super) fn restore_hardware(&mut self, id: u64) -> Result<()> {
        let tids = self.hardware[&id]
            .bindings
            .keys()
            .copied()
            .collect::<Vec<_>>();
        for tid in tids {
            self.restore_binding(id, tid)?;
        }
        let p = self.hardware.get_mut(&id).unwrap();
        p.view.enabled = false;
        p.view.armed = false;
        Ok(())
    }
    pub(super) fn hardware_action(&mut self, id: u64, action: &str) -> Result<()> {
        match action {
            "remove" | "disable" => {
                let p = self.hardware.get_mut(&id).unwrap();
                p.view.enabled = false;
                if action == "remove" {
                    p.remove_requested = true;
                    p.view.owner = "retiring".into();
                }
                let tid = self.pending.as_ref().unwrap().0.dwThreadId;
                self.restore_binding(id, tid)?;
                self.refresh_hardware(id);
            }
            "enable" => {
                if self.hardware[&id].remove_requested {
                    return Err(DebugError::new(
                        "state",
                        "removed point is awaiting physical thread cleanup",
                    ));
                }
                if self.hardware[&id].view.enabled {
                    return Ok(());
                }
                let before = self.hardware[&id]
                    .bindings
                    .keys()
                    .copied()
                    .collect::<std::collections::BTreeSet<_>>();
                if let Err(error) = self.enable_hardware(id) {
                    let added = self.hardware[&id]
                        .bindings
                        .keys()
                        .copied()
                        .filter(|t| !before.contains(t))
                        .collect::<Vec<_>>();
                    for tid in added {
                        if let Err(e) = self.restore_binding(id, tid) {
                            self.resume_poisoned = true;
                            return Err(e);
                        }
                    }
                    self.refresh_hardware(id);
                    return Err(error);
                }
            }
            _ => {
                return Err(DebugError::new(
                    "argument",
                    "hardware action is remove/disable/enable",
                ))
            }
        }
        Ok(())
    }
    pub(super) fn hardware_finish_disabled(&mut self, tid: u32) -> Result<()> {
        let ids = self
            .hardware
            .iter()
            .filter_map(|(&id, h)| (!h.view.enabled && h.bindings.contains_key(&tid)).then_some(id))
            .collect::<Vec<_>>();
        for id in ids {
            self.restore_binding(id, tid)?;
            self.refresh_hardware(id);
        }
        Ok(())
    }
    pub(super) fn hardware_cleanup_threads(&mut self) -> std::collections::BTreeSet<u32> {
        let mut tids = std::collections::BTreeSet::new();
        for h in self.hardware.values_mut() {
            h.view.enabled = false;
            h.remove_requested = true;
            h.view.owner = "retiring".into();
            tids.extend(h.bindings.keys().copied());
        }
        tids
    }
    pub(super) fn hardware_new_thread(&mut self, tid: u32) -> Result<()> {
        let ids = self
            .hardware
            .iter()
            .filter_map(|(&id, h)| (h.view.enabled && h.thread.is_none()).then_some(id))
            .collect::<Vec<_>>();
        for id in ids {
            self.bind_hardware(id, tid)?;
        }
        Ok(())
    }
    pub(super) fn hardware_thread_exited(&mut self, tid: u32) {
        self.retired_causes.remove(&tid);
        let ids = self.hardware.keys().copied().collect::<Vec<_>>();
        for id in ids {
            let h = self.hardware.get_mut(&id).unwrap();
            h.bindings.remove(&tid);
            h.view.slots.remove(&tid);
            h.view.threads.retain(|t| *t != tid);
            // A runtime TID must never be silently reused as a new thread's
            // authorization, nor block unrelated resumes after its owner exits.
            if h.thread == Some(tid) {
                h.view.enabled = false;
            }
            self.refresh_hardware(id);
        }
    }
    pub(super) fn hardware_ready(&self) -> Result<()> {
        for h in self.hardware.values().filter(|h| h.view.enabled) {
            let needed = h.thread.map_or_else(
                || self.threads.keys().copied().collect::<Vec<_>>(),
                |t| vec![t],
            );
            if needed.iter().any(|t| !h.bindings.contains_key(t)) {
                return Err(DebugError::new(
                    "hardware",
                    "enabled point lacks a thread binding; disable/remove it before continuing",
                ));
            }
        }
        Ok(())
    }
    pub(super) fn single_step_event(&mut self, tid: u32) -> Result<()> {
        let mut c = context(self.threads[&tid].0)?;
        let hits = self
            .hardware
            .iter()
            .filter_map(|(&id, h)| {
                h.bindings
                    .get(&tid)
                    .filter(|b| {
                        c.0.Dr6 & (1u64 << b.slot) != 0
                            && address(&c, b.slot)
                                == ura_core::parse_address(&h.view.address).unwrap()
                            && c.0.Dr7 & mask(b.slot) == control(h.view.kind, h.view.length, b.slot)
                    })
                    .map(|b| (id, b.slot))
            })
            .collect::<Vec<_>>();
        let retired = self.retired_causes.remove(&tid).unwrap_or_default();
        let owned = hits
            .iter()
            .fold(retired.0, |bits, (_, slot)| bits | (1u64 << slot));
        let has_execute = retired.1
            || hits
                .iter()
                .any(|(id, _)| self.hardware[id].view.kind == BreakpointKind::HardwareExecute);
        // Data traps occur after the instruction; execution faults occur before.
        // Account for Windows normalizing away BS on a completed TF+data trap.
        let own_step = retired.0 & (1 << 14) == 0
            && (self.step.as_ref().is_some_and(|s| s.thread == tid)
                || self.owned_traps.contains(&tid))
            && (c.0.Dr6 & (1 << 14) != 0
                || (!has_execute && c.0.Dr6 & (15 & !owned | (1 << 13) | (1 << 15)) == 0));
        let external = (c.0.Dr6 & 15 & !owned) != 0
            || c.0.Dr6 & ((1 << 13) | (1 << 15)) != 0
            || (c.0.Dr6 & (1 << 14) != 0 && !own_step && retired.0 & (1 << 14) == 0);
        if !external && (own_step || owned != 0) {
            self.pending.as_mut().unwrap().1 = DBG_CONTINUE;
        }
        if self.draining_hardware {
            self.event(
                tid,
                "cleanupDebugCause",
                format!(
                    "dr6={}, owned={}, tf={}, ownStep={own_step}, external={external}",
                    hex(c.0.Dr6),
                    hex(owned),
                    self.owned_traps.contains(&tid)
                ),
            );
        }
        c.0.Dr6 &= !owned;
        if own_step {
            c.0.EFlags &= !0x100;
            c.0.Dr6 &= !(1 << 14);
        }
        if hits
            .iter()
            .any(|(id, _)| self.hardware[id].view.kind == BreakpointKind::HardwareExecute)
        {
            c.0.EFlags |= 1 << 16;
        }
        set_context(self.threads[&tid].0, &c)?;
        if own_step {
            self.owned_traps.remove(&tid);
        }
        let step = if own_step {
            if self.step.as_ref().is_some_and(|s| s.thread == tid) {
                self.release_step()?
            } else if self.parked_step.as_ref().is_some_and(|s| s.thread == tid) {
                self.parked_step.take()
            } else {
                None
            }
        } else {
            None
        };
        let regs = registers(tid, &c);
        let mut stop = false;
        for (id, _) in hits {
            let matched =
                hardware::matches_condition(&mut self.hardware.get_mut(&id).unwrap().view, &regs);
            self.event(
                tid,
                "hardwareBreakpoint",
                format!("id={id}, ip={}", hex(c.0.Rip)),
            );
            match matched {
                Ok(true) => stop |= self.hardware[&id].view.enabled,
                Ok(false) => {}
                Err(e) => {
                    self.event(tid, "conditionError", e.message);
                    stop = true;
                }
            }
        }
        self.hardware_finish_disabled(tid)?;
        if self.draining_hardware && self.cleanup_threads.contains(&tid) {
            // An execution breakpoint faults before the TF instruction completes.
            // Its event is still the required handoff for this thread's owned TF.
            self.finish_cleanup_thread(tid)?;
            return self.pause_event(
                "cleanupThread",
                if external {
                    DBG_EXCEPTION_NOT_HANDLED
                } else {
                    DBG_CONTINUE
                },
            );
        }
        if external {
            self.stop_instruction_trace("externalDebugException");
            self.abort_step()?;
            self.cancel_temporary()?;
            return self.pause_event("applicationException", DBG_EXCEPTION_NOT_HANDLED);
        }
        if stop {
            self.stop_instruction_trace("breakpoint");
            self.abort_step()?;
            self.cancel_temporary()?;
            return self.pause_event("hardwareBreakpoint", DBG_CONTINUE);
        }
        if step.is_some() && self.trace_instruction_stop(tid, &regs)? {
            return Ok(());
        }
        if step.as_ref().is_some_and(|s| s.stop) {
            self.cancel_temporary()?;
            return self.pause_event("singleStep", DBG_CONTINUE);
        }
        if retired.0 != 0 && self.draining_hardware {
            return self.pause_event("hardwareCleanup", DBG_CONTINUE);
        }
        if own_step || owned != 0 {
            self.view.state = State::Running;
            return self.continue_pending(DBG_CONTINUE);
        }
        self.stop_instruction_trace("applicationException");
        self.pause_event("applicationException", DBG_EXCEPTION_NOT_HANDLED)
    }
}
