use super::*;
impl WindowsBackend {
    pub(super) fn run_to(&mut self, address: u64, stack: Option<u64>, owner: &str) -> Result<()> {
        self.paused()?;
        if self.step.is_some() || self.control.is_some() {
            return Err(DebugError::new(
                "state",
                "an interrupted step/control operation still owns resources",
            ));
        }
        let tid = self.pending.as_ref().unwrap().0.dwThreadId;
        if self.view.selected_thread != Some(tid) {
            return Err(DebugError::new("thread", "select the stopped event thread"));
        }
        let c = context(self.threads[&tid].0)?;
        if address == c.0.Rip {
            return Err(DebugError::new(
                "argument",
                "run destination is already the current instruction",
            ));
        }
        let mapping = memory(self.process()?, address, 1)?;
        let protection = mapping["region"]["protection"].as_u64().unwrap_or(0);
        if mapping["read"].as_u64() != Some(1) || protection & 0xf0 == 0 || protection & 0x100 != 0
        {
            return Err(DebugError::new(
                "memory",
                "run destination must be readable executable committed memory",
            ));
        }
        let borrowed = self.points.get(&address);
        if borrowed.is_some_and(|p| !p.view.enabled || !p.view.armed) {
            return Err(DebugError::new(
                "conflict",
                "destination has a disabled/unarmed user breakpoint; enable or remove it first",
            ));
        }
        if borrowed.is_none() {
            self.add_point(address, Some((tid, stack.unwrap_or(u64::MAX))), owner)?;
        }
        self.control = Some((address, tid, stack, owner.into()));
        if let Err(error) = self.resume(None, true) {
            self.cancel_temporary()?;
            return Err(error);
        }
        Ok(())
    }
    pub(super) fn step_out(&mut self) -> Result<()> {
        let (tid, h) = self.thread(None)?;
        if self.pending.as_ref().unwrap().0.dwThreadId != tid {
            return Err(DebugError::new(
                "thread",
                "step-out requires the stopped event thread",
            ));
        }
        let current = context(h)?;
        let frames = stack(self.process()?, h, tid, &self.view.modules, 3)?;
        let caller = frames["frames"].get(1).ok_or_else(|| {
            DebugError::new("unwind", "no validated caller frame; step-out unavailable")
        })?;
        let ip = caller["instructionPointer"]
            .as_str()
            .and_then(|s| ura_core::parse_address(s).ok())
            .ok_or_else(|| DebugError::new("unwind", "caller instruction unavailable"))?;
        let sp = caller["stackPointer"]
            .as_str()
            .and_then(|s| ura_core::parse_address(s).ok())
            .ok_or_else(|| DebugError::new("unwind", "caller stack unavailable"))?;
        if sp <= current.0.Rsp || sp - current.0.Rsp > 8 * 1024 * 1024 {
            return Err(DebugError::new(
                "unwind",
                "caller frame does not establish a bounded advancing stack; step-out unavailable",
            ));
        }
        self.run_to(ip, Some(sp), "stepOut")
    }
}
