//! Separate, deny-by-default execution/attach policy. Static write access grants neither.
use crate::{PathPolicy, ServiceError};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::PathBuf;
use ura_debugger::{Command, Controller, LaunchConfig, Snapshot};

#[derive(Debug, Clone, Default)]
pub struct DebugPermissions {
    pub launch: bool,
    pub attach: bool,
    pub terminate_attached: bool,
    /// Exact executables, not directory roots. Identity is pinned when configured.
    pub targets: Vec<PathBuf>,
    pub attach_pids: Vec<u32>,
}
pub struct DebugService {
    policy: PathPolicy,
    permissions: DebugPermissions,
    project_writes: bool,
    project_grants: std::collections::BTreeSet<PathBuf>,
    targets: Vec<(PathBuf, String)>,
    controller: Option<Controller>,
}
impl DebugService {
    pub fn new(policy: PathPolicy, permissions: DebugPermissions) -> Result<Self, ServiceError> {
        if permissions.targets.len() > 64 || permissions.attach_pids.len() > 64 {
            return Err(ServiceError::LimitExceeded(
                "debug allowlists are limited to 64 entries".into(),
            ));
        }
        let mut targets = Vec::new();
        for path in &permissions.targets {
            let path = policy.allow_read(path)?;
            let loaded = ura_core::analyze_path(&path)?;
            targets.push((path, loaded.view().sha256));
        }
        Ok(Self {
            policy,
            permissions,
            targets,
            controller: None,
            project_writes: false,
            project_grants: Default::default(),
        })
    }
    pub fn with_project_writes(mut self, enabled: bool) -> Self {
        self.project_writes = enabled;
        self
    }
    /// Native UI only: explicitly grant the exact project the user selected.
    /// The MCP/JSON protocol never exposes this policy-changing operation.
    pub fn grant_project(&mut self, path: &std::path::Path) -> Result<(), ServiceError> {
        let path = path
            .canonicalize()
            .map_err(|e| ServiceError::Io(e.to_string()))?;
        self.project_grants.insert(path);
        Ok(())
    }
    fn project_path(&self, path: &std::path::Path, write: bool) -> Result<PathBuf, ServiceError> {
        let resolved = if write {
            self.policy.allow_write(path)
        } else {
            self.policy.allow_read(path)
        };
        resolved.or_else(|error| {
            let absolute = path.canonicalize().map_err(|_| error)?;
            if self.project_grants.contains(&absolute) {
                Ok(absolute)
            } else {
                Err(ServiceError::PathDenied(absolute.display().to_string()))
            }
        })
    }
    pub fn snapshot(&self) -> Snapshot {
        self.controller.as_ref().map_or(
            Snapshot {
                schema_version: 1,
                ..Default::default()
            },
            Controller::snapshot,
        )
    }
    fn check_target(&self, path: &std::path::Path) -> Result<PathBuf, ServiceError> {
        let path = self.policy.allow_read(path)?;
        let expected = self
            .targets
            .iter()
            .find(|(p, _)| p == &path)
            .ok_or_else(|| {
                ServiceError::InvalidArgument(
                    "debug target is not in the exact executable allowlist".into(),
                )
            })?;
        let loaded = ura_core::analyze_path(&path)?;
        if loaded.view().sha256 != expected.1 {
            return Err(ServiceError::InvalidArgument(
                "allowed executable identity changed; restart with reviewed target policy".into(),
            ));
        }
        Ok(path)
    }
    pub fn launch(&mut self, mut config: LaunchConfig) -> Result<Value, ServiceError> {
        if !self.permissions.launch {
            return Err(ServiceError::InvalidArgument(
                "debug launching disabled; requires --enable-debug-launch and --debug-target FILE"
                    .into(),
            ));
        }
        config.executable = self.check_target(&config.executable)?;
        config.expected_sha256 = self
            .targets
            .iter()
            .find(|(p, _)| p == &config.executable)
            .map(|(_, h)| h.clone());
        if let Some(directory) = &config.working_directory {
            config.working_directory = Some(self.policy.allow_read(directory)?);
        }
        self.request(None, Command::Launch(config))
    }
    pub fn attach(&mut self, pid: u32, executable: PathBuf) -> Result<Value, ServiceError> {
        if !self.permissions.attach || !self.permissions.attach_pids.contains(&pid) {
            return Err(ServiceError::InvalidArgument("attach disabled or PID not explicitly allowed; requires --enable-debug-attach, --debug-pid and --debug-target".into()));
        }
        let executable = self.check_target(&executable)?;
        let expected_sha256 = self
            .targets
            .iter()
            .find(|(p, _)| p == &executable)
            .map(|(_, h)| h.clone());
        self.request(
            None,
            Command::Attach {
                pid,
                executable,
                expected_sha256,
            },
        )
    }
    pub fn status(&self, session: Option<&str>) -> Result<Value, ServiceError> {
        let snapshot = self.snapshot();
        if session.is_some() && session != snapshot.session.as_deref() {
            return Err(ServiceError::InvalidArgument(
                "stale or unknown debugger session".into(),
            ));
        }
        Ok(json!(snapshot))
    }
    /// Bounded local JSON-line/MCP adapter. Addresses stay lossless hexadecimal strings.
    pub fn rpc(&mut self, value: Value) -> Result<Value, ServiceError> {
        let request: DebugRequest = serde_json::from_value(value)
            .map_err(|e| ServiceError::InvalidArgument(e.to_string()))?;
        let address = |text: &str| ura_core::parse_address(text).map_err(ServiceError::from);
        match request {
            DebugRequest::Launch {
                executable,
                arguments,
                working_directory,
                environment,
                break_at_entry,
            } => self.launch(LaunchConfig {
                executable,
                expected_sha256: None,
                arguments,
                working_directory,
                environment,
                break_at_entry,
            }),
            DebugRequest::Attach { pid, executable } => self.attach(pid, executable),
            DebugRequest::Status { session } => self.status(session.as_deref()),
            DebugRequest::Continue {
                session,
                pass_exception,
            } => self.command(&session, Command::Continue { pass_exception }),
            DebugRequest::Pause { session } => self.command(&session, Command::Pause),
            DebugRequest::Step { session, over } => self.command(&session, Command::Step { over }),
            DebugRequest::Detach { session } => self.command(&session, Command::Detach),
            DebugRequest::Terminate { session } => self.command(&session, Command::Terminate),
            DebugRequest::Registers { session, thread } => {
                self.command(&session, Command::Registers { thread })
            }
            DebugRequest::ReadMemory {
                session,
                address: a,
                length,
            } => self.command(
                &session,
                Command::Memory {
                    address: address(&a)?,
                    length,
                },
            ),
            DebugRequest::CallStack {
                session,
                thread,
                limit,
            } => self.command(&session, Command::Stack { thread, limit }),
            DebugRequest::Disassembly {
                session,
                address: a,
                count,
            } => self.command(
                &session,
                Command::Disassembly {
                    address: address(&a)?,
                    count,
                },
            ),
            DebugRequest::Breakpoints {
                session,
                action,
                address: a,
                id,
                project,
            } => {
                if action == "save" || action == "restore" {
                    return self.project_breakpoints(
                        &session,
                        &action,
                        project.ok_or_else(|| {
                            ServiceError::InvalidArgument("project required".into())
                        })?,
                    );
                }
                if action == "list" {
                    let status = self.status(Some(&session))?;
                    Ok(status["breakpoints"].clone())
                } else {
                    self.command(
                        &session,
                        Command::Breakpoint {
                            action,
                            address: a.map(|a| address(&a)).transpose()?,
                            id,
                        },
                    )
                }
            }
            DebugRequest::Threads { session } => {
                Ok(self.status(Some(&session))?["threads"].clone())
            }
            DebugRequest::Modules { session } => {
                Ok(self.status(Some(&session))?["modules"].clone())
            }
            DebugRequest::Events { session } => {
                let s = self.status(Some(&session))?;
                Ok(json!({"events":s["events"],"dropped":s["eventsDropped"]}))
            }
        }
    }
    fn project_breakpoints(
        &mut self,
        session: &str,
        action: &str,
        project: PathBuf,
    ) -> Result<Value, ServiceError> {
        self.status(Some(session))?;
        let snapshot = self.snapshot();
        let module = snapshot
            .modules
            .iter()
            .find(|m| m.sha256.is_some())
            .ok_or_else(|| {
                ServiceError::InvalidArgument("main image identity unavailable".into())
            })?;
        let hash = module.sha256.as_ref().unwrap();
        let project = self.project_path(&project, action == "save")?;
        let saved = ura_project::read_project(&project)?;
        if !saved.project.binary_hash.eq_ignore_ascii_case(hash) {
            return Err(ServiceError::ProjectBinaryMismatch);
        }
        if action == "save" {
            if !self.project_writes {
                return Err(ServiceError::WriteDisabled);
            }

            let definitions = snapshot
                .breakpoints
                .iter()
                .filter(|p| p.owner == "user" && p.module == module.path)
                .filter_map(|p| {
                    p.rva.as_ref().map(|rva| ura_project::DebugBreakpoint {
                        module_sha256: hash.clone(),
                        rva: rva.clone(),
                        enabled: p.enabled,
                    })
                })
                .collect::<Vec<_>>();
            ura_project::save_debug_breakpoints(&project, &definitions)?;
            return Ok(json!({"saved":definitions.len()}));
        }
        let definitions = saved.debug_breakpoints;
        if snapshot.state != ura_debugger::State::Paused {
            return Err(ServiceError::InvalidArgument(
                "pause before restoring breakpoint definitions".into(),
            ));
        }
        let base = ura_core::parse_address(&module.base)?;
        let mut addresses = Vec::new();
        for definition in definitions {
            if definition.module_sha256 != *hash {
                return Err(ServiceError::ProjectBinaryMismatch);
            }
            let rva = ura_core::parse_address(&definition.rva)?;
            if rva >= module.size {
                return Err(ServiceError::InvalidArgument(
                    "saved breakpoint RVA outside runtime module".into(),
                ));
            }
            addresses.push((
                base.checked_add(rva).ok_or_else(|| {
                    ServiceError::InvalidArgument("runtime breakpoint overflow".into())
                })?,
                definition.enabled,
            ));
        }
        for (address, _) in &addresses {
            if snapshot
                .breakpoints
                .iter()
                .any(|p| p.address == ura_debugger::hex(*address))
            {
                return Err(ServiceError::InvalidArgument("saved breakpoint address already owned; restoration has not changed any points".into()));
            }
        }
        let mut added = Vec::new();
        let result = (|| {
            for (address, enabled) in addresses {
                self.command(
                    session,
                    Command::Breakpoint {
                        action: "set".into(),
                        address: Some(address),
                        id: None,
                    },
                )?;
                let id = self
                    .snapshot()
                    .breakpoints
                    .iter()
                    .find(|p| p.address == ura_debugger::hex(address))
                    .unwrap()
                    .id;
                added.push(id);
                if !enabled {
                    self.command(
                        session,
                        Command::Breakpoint {
                            action: "disable".into(),
                            address: None,
                            id: Some(id),
                        },
                    )?;
                }
            }
            Ok::<_, ServiceError>(())
        })();
        if let Err(error) = result {
            let mut remaining = Vec::new();
            for &id in added.iter().rev() {
                if self
                    .command(
                        session,
                        Command::Breakpoint {
                            action: "remove".into(),
                            address: None,
                            id: Some(id),
                        },
                    )
                    .is_err()
                {
                    remaining.push(id);
                }
            }
            return Err(ServiceError::InvalidArgument(format!(
                "restore failed: {error}; rollback remaining breakpoint IDs: {remaining:?}"
            )));
        }
        Ok(json!({"restored":added.len()}))
    }

    pub fn command(&mut self, session: &str, command: Command) -> Result<Value, ServiceError> {
        if self.snapshot().reason.as_deref() == Some("cleanupPending") {
            return Err(ServiceError::InvalidArgument("debug owner is retrying required cleanup; status remains available and control commands are unavailable".into()));
        }
        if matches!(command, Command::Launch(_) | Command::Attach { .. }) {
            return Err(ServiceError::InvalidArgument(
                "use policy-checked launch/attach entry points".into(),
            ));
        }
        if matches!(command, Command::Terminate)
            && self.snapshot().attached
            && !self.permissions.terminate_attached
        {
            return Err(ServiceError::InvalidArgument("terminating attached targets requires separate --enable-debug-terminate-attached permission".into()));
        }
        self.request(Some(session), command)
    }
    fn request(&mut self, session: Option<&str>, command: Command) -> Result<Value, ServiceError> {
        if self.controller.is_none() {
            if !matches!(command, Command::Launch(_) | Command::Attach { .. }) {
                return Err(ServiceError::InvalidArgument("no debugger session".into()));
            }
            self.controller = Some(Controller::new());
        }
        self.controller
            .as_ref()
            .unwrap()
            .command(session, command)
            .map_err(|e| ServiceError::InvalidArgument(format!("{}: {}", e.code, e.message)))
    }
}
fn yes() -> bool {
    true
}
fn stack_limit() -> usize {
    32
}
fn disasm_limit() -> usize {
    32
}
fn list() -> String {
    "list".into()
}
#[derive(Debug, Deserialize)]
#[serde(
    tag = "operation",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum DebugRequest {
    Launch {
        executable: PathBuf,
        #[serde(default)]
        arguments: Vec<String>,
        working_directory: Option<PathBuf>,
        #[serde(default)]
        environment: std::collections::BTreeMap<String, String>,
        #[serde(default = "yes")]
        break_at_entry: bool,
    },
    Attach {
        pid: u32,
        executable: PathBuf,
    },
    Status {
        session: Option<String>,
    },
    Continue {
        session: String,
        #[serde(default = "yes")]
        pass_exception: bool,
    },
    Pause {
        session: String,
    },
    Step {
        session: String,
        #[serde(default)]
        over: bool,
    },
    Detach {
        session: String,
    },
    Terminate {
        session: String,
    },
    Registers {
        session: String,
        thread: Option<u32>,
    },
    ReadMemory {
        session: String,
        address: String,
        length: usize,
    },
    CallStack {
        session: String,
        thread: Option<u32>,
        #[serde(default = "stack_limit")]
        limit: usize,
    },
    Disassembly {
        session: String,
        address: String,
        #[serde(default = "disasm_limit")]
        count: usize,
    },
    Breakpoints {
        session: String,
        #[serde(default = "list")]
        action: String,
        address: Option<String>,
        id: Option<u64>,
        project: Option<PathBuf>,
    },
    Threads {
        session: String,
    },
    Modules {
        session: String,
    },
    Events {
        session: String,
    },
}
