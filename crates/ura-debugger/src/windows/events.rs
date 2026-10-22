use super::*;
impl WindowsBackend {
    pub(super) fn on_event(&mut self, event: DEBUG_EVENT) -> Result<()> {
        unsafe {
            let tid = event.dwThreadId;
            let code = event.dwDebugEventCode;
            self.pending = Some((event, DBG_CONTINUE));
            match code {
                CREATE_PROCESS_DEBUG_EVENT => {
                    let data = event.u.CreateProcessInfo;
                    let file = Handle::new(data.hFile).ok();
                    let path = file
                        .as_ref()
                        .and_then(|f| image_path(f.0))
                        .or_else(|| self.view.executable.clone());
                    let process = duplicate(data.hProcess)?;
                    let thread = duplicate(data.hThread)?;
                    self.event_process = Some(data.hProcess);
                    self.event_threads.insert(tid, data.hThread);
                    self.process = Some(process);
                    architecture(self.process()?)?;
                    self.threads.insert(tid, thread);
                    self.view.threads.push(Thread {
                        id: tid,
                        start_address: hex(data.lpStartAddress.map_or(0, |p| p as usize as u64)),
                    });
                    let base = data.lpBaseOfImage as u64;
                    let mut module = module(self.process()?, base, path);
                    if let Some(image) = &self.image {
                        if let Some(file) = &file {
                            if debug_file_hash(file.0)? != image.hash {
                                return Err(DebugError::new("identity","Windows debug-event image differs from the authorized held image"));
                            }
                        } else if self.view.attached {
                            return Err(DebugError::new("identity","attached image identity could not be established from the Windows debug event"));
                        }
                        module.sha256 = Some(image.hash.clone());
                        module.preferred_base = Some(hex(image.preferred));
                        module.entry_point = image
                            .entry
                            .checked_sub(image.preferred)
                            .and_then(|rva| base.checked_add(rva))
                            .map(hex);
                    }
                    self.view.modules.push(module);
                    self.event(
                        tid,
                        "processCreated",
                        format!("main module at {}", hex(base)),
                    );
                    if self.break_at_entry {
                        let image = self.image.as_ref().unwrap();
                        let entry = base
                            .checked_add(image.entry - image.preferred)
                            .ok_or_else(|| DebugError::new("mapping", "entry overflow"))?;
                        self.add_point(entry, None, "entry")?;
                    }
                }
                CREATE_THREAD_DEBUG_EVENT => {
                    if self.threads.len() >= 1024 {
                        return Err(DebugError::new("limit", "thread limit reached"));
                    }
                    let data = event.u.CreateThread;
                    self.event_threads.insert(tid, data.hThread);
                    let handle = duplicate(data.hThread)?;
                    let start = data.lpStartAddress.map_or(0, |p| p as usize as u64);
                    let debugger_break = self.pause_requested && self.remote_break == Some(start);
                    if debugger_break {
                        self.break_threads.insert(tid);
                    }
                    if let Some(step) = self.step.as_mut() {
                        if tid != step.thread && !debugger_break {
                            if SuspendThread(handle.0) == u32::MAX {
                                return Err(error(
                                    "SuspendThread new thread during displaced instruction",
                                ));
                            }
                            step.frozen.push(tid);
                        }
                    }
                    self.threads.insert(tid, handle);
                    self.view.threads.push(Thread {
                        id: tid,
                        start_address: hex(data.lpStartAddress.map_or(0, |p| p as usize as u64)),
                    });
                    self.event(tid, "threadCreated", "thread observed");
                }
                EXIT_THREAD_DEBUG_EVENT => {
                    self.event(
                        tid,
                        "threadExited",
                        format!("exit {}", event.u.ExitThread.dwExitCode),
                    );
                    if self.step.as_ref().is_some_and(|s| s.thread == tid) {
                        self.release_step()?;
                        self.displaced = None;
                        self.cancel_temporary()?;
                    }
                    self.continue_pending(DBG_CONTINUE)?;
                    self.event_threads.remove(&tid);
                    self.threads.remove(&tid);
                    self.view.threads.retain(|t| t.id != tid);
                    return Ok(());
                }
                LOAD_DLL_DEBUG_EVENT => {
                    let data = event.u.LoadDll;
                    let file = Handle::new(data.hFile).ok();
                    let path = file.as_ref().and_then(|f| image_path(f.0));
                    if self.view.modules.len() >= 512 {
                        return Err(DebugError::new("limit", "module limit reached"));
                    }
                    let loaded = module(self.process()?, data.lpBaseOfDll as u64, path);
                    if let Some((point, remote)) = debug_helpers(&loaded) {
                        self.system_break = Some(point);
                        self.remote_break = Some(remote);
                    }
                    self.view.modules.push(loaded);
                    self.event(tid, "moduleLoaded", hex(data.lpBaseOfDll as u64));
                }
                UNLOAD_DLL_DEBUG_EVENT => {
                    let base = event.u.UnloadDll.lpBaseOfDll as u64;
                    if let Some(module) = self.view.modules.iter().find(|m| m.base == hex(base)) {
                        let end = base.saturating_add(module.size);
                        self.points.retain(|&a, _| a < base || a >= end);
                    }
                    self.view.modules.retain(|m| m.base != hex(base));
                    self.event(tid, "moduleUnloaded", hex(base));
                }
                EXIT_PROCESS_DEBUG_EVENT => {
                    self.view.exit_code = Some(event.u.ExitProcess.dwExitCode);
                    self.event(
                        tid,
                        "processExited",
                        format!("exit {}", event.u.ExitProcess.dwExitCode),
                    );
                    self.continue_pending(DBG_CONTINUE)?;
                    self.event_process = None;
                    self.event_threads.clear();
                    self.process = None;
                    self.threads.clear();
                    self.points.clear();
                    self.step = None;
                    self.displaced = None;
                    self.image = None;
                    self.view.state = State::Exited;
                    self.view.registers = None;
                    self.view.threads.clear();
                    self.view.modules.clear();
                    return Ok(());
                }
                EXCEPTION_DEBUG_EVENT => {
                    for loaded in &mut self.view.modules {
                        let updated = module(
                            self.process.as_ref().unwrap().0,
                            ura_core::parse_address(&loaded.base).unwrap_or(0),
                            loaded.path.clone(),
                        );
                        loaded.path = updated.path;
                        loaded.size = updated.size;
                        if self.remote_break.is_none() {
                            if let Some((point, remote)) = debug_helpers(loaded) {
                                self.system_break = Some(point);
                                self.remote_break = Some(remote);
                            }
                        }
                    }
                    let exception = event.u.Exception;
                    let code = exception.ExceptionRecord.ExceptionCode;
                    let address = exception.ExceptionRecord.ExceptionAddress as u64;
                    self.view.exception_code = Some(hex(code as u32 as u64));
                    self.view.first_chance = Some(exception.dwFirstChance != 0);
                    self.event(
                        tid,
                        "exception",
                        format!(
                            "{} at {}, firstChance={}",
                            hex(code as u32 as u64),
                            hex(address),
                            exception.dwFirstChance != 0
                        ),
                    );
                    if code == EXCEPTION_SINGLE_STEP
                        && self.step.as_ref().is_some_and(|s| s.thread == tid)
                    {
                        let handle = self.threads[&tid].0;
                        let mut c = context(handle)?;
                        c.0.EFlags &= !0x100;
                        set_context(handle, &c)?;
                        let step = self.release_step()?.unwrap();
                        if step.stop {
                            self.cancel_temporary()?;
                            return self.pause_event("singleStep", DBG_CONTINUE);
                        }
                        self.view.state = State::Running;
                    } else if code == EXCEPTION_BREAKPOINT
                        && self.points.get(&address).is_some_and(|p| p.view.armed)
                    {
                        self.repair = Some((address, tid));
                        self.repair_breakpoint()?;
                        let c = context(self.threads[&tid].0)?;
                        let point = self.points.get_mut(&address).unwrap();
                        point.view.hits += 1;
                        let stop = point
                            .temporary
                            .map_or(true, |(thread, stack)| thread == tid && stack == c.0.Rsp);
                        let owner = point.view.owner.clone();
                        self.displaced = Some((address, tid));
                        self.pause_event("breakpoint", DBG_CONTINUE)?;
                        if stop {
                            if owner == "stepOver" || owner == "entry" {
                                self.points.remove(&address);
                                self.displaced = None;
                            }
                            self.cancel_temporary()?;
                            return Ok(());
                        }
                        return self.resume(None, true);
                    } else if code == EXCEPTION_BREAKPOINT
                        && self.view.modules.iter().any(|m| {
                            m.path.as_ref().is_some_and(|p| {
                                std::path::Path::new(p)
                                    .file_name()
                                    .is_some_and(|n| n.eq_ignore_ascii_case("ntdll.dll"))
                            }) && ura_core::parse_address(&m.base)
                                .is_ok_and(|b| address >= b && address - b < m.size)
                        })
                        && (self.initial_break
                            || (self.pause_requested && self.break_threads.contains(&tid)))
                    {
                        let initial = self.initial_break;
                        self.initial_break = false;
                        self.pause_requested = false;
                        self.abort_step()?;
                        self.cancel_temporary()?;
                        if !(initial && self.break_at_entry) {
                            return self.pause_event(
                                if initial {
                                    "initialBreakpoint"
                                } else {
                                    "pause"
                                },
                                DBG_CONTINUE,
                            );
                        }
                    } else {
                        // Application first/second chance exceptions remain pending and default to NOT_HANDLED.
                        self.abort_step()?;
                        self.cancel_temporary()?;
                        return self.pause_event("applicationException", DBG_EXCEPTION_NOT_HANDLED);
                    }
                }
                OUTPUT_DEBUG_STRING_EVENT => self.event(
                    tid,
                    "debugString",
                    "target emitted debug output (not interpreted as a command)",
                ),
                _ => self.event(tid, "debugEvent", format!("event {code}")),
            }
            self.continue_pending(DBG_CONTINUE)?;
            Ok(())
        }
    }
    pub(super) fn abort_step(&mut self) -> Result<()> {
        if let Some(step) = &self.step {
            if let Some(thread) = self.threads.get(&step.thread) {
                let mut c = context(thread.0)?;
                c.0.EFlags &= !0x100;
                set_context(thread.0, &c)?;
            }
        }
        self.release_step()?;
        Ok(())
    }
    pub(super) fn cancel_temporary(&mut self) -> Result<()> {
        let remove = self
            .points
            .iter()
            .filter_map(|(&a, p)| (p.view.owner == "stepOver").then_some(a))
            .collect::<Vec<_>>();
        for address in remove {
            self.remove_point(address)?;
        }
        Ok(())
    }
}
