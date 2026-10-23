use super::*;
use ura_debugger::{
    BreakpointConfig, BreakpointKind, CaptureAction, SymbolAction, TraceAction, TraceConfig,
};
pub(super) fn handles(value: &Value) -> bool {
    matches!(
        value["operation"].as_str(),
        Some(
            "capabilities"
                | "configureBreakpoint"
                | "setCondition"
                | "stepOut"
                | "runTo"
                | "trace"
                | "memoryRegions"
                | "snapshot"
                | "symbols"
        )
    )
}
fn one() -> u64 {
    1
}
fn length() -> u8 {
    1
}
fn page() -> usize {
    128
}
fn read() -> String {
    "read".into()
}
#[derive(Deserialize)]
#[serde(
    tag = "operation",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum Request {
    Capabilities,
    ConfigureBreakpoint {
        session: String,
        address: String,
        #[serde(default)]
        kind: BreakpointKind,
        #[serde(default = "length")]
        length: u8,
        thread: Option<u32>,
        condition: Option<String>,
        #[serde(default = "one")]
        hit_after: u64,
        #[serde(default = "one")]
        hit_every: u64,
    },
    SetCondition {
        session: String,
        id: u64,
        condition: Option<String>,
        #[serde(default = "one")]
        hit_after: u64,
        #[serde(default = "one")]
        hit_every: u64,
    },
    StepOut {
        session: String,
    },
    RunTo {
        session: String,
        address: String,
    },
    Trace {
        session: String,
        #[serde(default = "read")]
        action: String,
        config: Option<TraceConfig>,
        #[serde(default)]
        after: u64,
        #[serde(default = "page")]
        limit: usize,
        destination: Option<PathBuf>,
    },
    MemoryRegions {
        session: String,
        #[serde(default)]
        address: Option<String>,
        #[serde(default = "page")]
        limit: usize,
    },
    Snapshot {
        session: String,
        action: String,
        id: Option<u64>,
        other: Option<u64>,
        address: Option<String>,
        length: Option<usize>,
        #[serde(default = "page")]
        count: usize,
        destination: Option<PathBuf>,
    },
    Symbols {
        session: String,
        action: String,
        base: Option<String>,
        pdb: Option<PathBuf>,
        address: Option<String>,
    },
}
impl DebugService {
    pub(super) fn advanced_rpc(&mut self, value: Value) -> Result<Value, ServiceError> {
        let req: Request = serde_json::from_value(value)
            .map_err(|e| ServiceError::InvalidArgument(e.to_string()))?;
        let address = |s: &str| ura_core::parse_address(s).map_err(ServiceError::from);
        let required =
            |name: &str| ServiceError::InvalidArgument(format!("{name} required for this action"));
        match req {
            Request::Capabilities => Ok(ura_debugger::capabilities()),
            Request::ConfigureBreakpoint {
                session,
                address: a,
                kind,
                length,
                thread,
                condition,
                hit_after,
                hit_every,
            } => self.command(
                &session,
                Command::ConfigureBreakpoint(BreakpointConfig {
                    address: address(&a)?,
                    kind,
                    length,
                    thread,
                    condition,
                    hit_after,
                    hit_every,
                }),
            ),
            Request::SetCondition {
                session,
                id,
                condition,
                hit_after,
                hit_every,
            } => self.command(
                &session,
                Command::SetCondition {
                    id,
                    condition,
                    hit_after,
                    hit_every,
                },
            ),
            Request::StepOut { session } => self.command(&session, Command::StepOut),
            Request::RunTo {
                session,
                address: a,
            } => self.command(
                &session,
                Command::RunTo {
                    address: address(&a)?,
                },
            ),
            Request::MemoryRegions {
                session,
                address: a,
                limit,
            } => self.command(
                &session,
                Command::Regions {
                    address: a.map(|a| address(&a)).transpose()?.unwrap_or(0),
                    limit,
                },
            ),
            Request::Trace {
                session,
                action,
                config,
                after,
                limit,
                destination,
            } => {
                let command = match action.as_str() {
                    "start" => TraceAction::Start(config.unwrap_or_default()),
                    "stop" => TraceAction::Stop,
                    "clear" => TraceAction::Clear,
                    "read" => TraceAction::Read { after, limit },
                    "export" => {
                        self.check_evidence_export()?;
                        TraceAction::Export
                    }
                    _ => {
                        return Err(ServiceError::InvalidArgument(
                            "trace action: start/stop/clear/read/export".into(),
                        ))
                    }
                };
                let result = self.command(&session, Command::Trace(command))?;
                if action == "export" {
                    self.export_evidence(
                        result,
                        &destination.ok_or_else(|| required("destination"))?,
                    )
                } else {
                    Ok(result)
                }
            }
            Request::Snapshot {
                session,
                action,
                id,
                other,
                address: a,
                length,
                count,
                destination,
            } => {
                let command =
                    match action.as_str() {
                        "capture" => CaptureAction::Capture {
                            address: address(&a.ok_or_else(|| required("address"))?)?,
                            length: length.ok_or_else(|| required("length"))?,
                        },
                        "list" => CaptureAction::List,
                        "info" => CaptureAction::Info {
                            id: id.ok_or_else(|| required("id"))?,
                        },
                        "remove" => CaptureAction::Remove {
                            id: id.ok_or_else(|| required("id"))?,
                        },
                        "compare" => CaptureAction::Compare {
                            id: id.ok_or_else(|| required("id"))?,
                            other,
                        },
                        "disassembly" => CaptureAction::Disassembly {
                            id: id.ok_or_else(|| required("id"))?,
                            address: address(&a.ok_or_else(|| required("address"))?)?,
                            count,
                        },
                        "export" => {
                            self.check_evidence_export()?;
                            CaptureAction::Export {
                                id: id.ok_or_else(|| required("id"))?,
                            }
                        }
                        _ => return Err(ServiceError::InvalidArgument(
                            "snapshot action: capture/list/info/remove/compare/disassembly/export"
                                .into(),
                        )),
                    };
                let result = self.command(&session, Command::Capture(command))?;
                if action == "export" {
                    self.export_evidence(
                        result,
                        &destination.ok_or_else(|| required("destination"))?,
                    )
                } else {
                    Ok(result)
                }
            }
            Request::Symbols {
                session,
                action,
                base,
                pdb,
                address: a,
            } => {
                let action = match action.as_str() {
                    "load" => {
                        let path = self
                            .policy
                            .allow_read(&pdb.ok_or_else(|| required("pdb"))?)?;
                        if path.to_string_lossy().starts_with(r"\\?\UNC\")
                            || path.to_string_lossy().starts_with("smb:")
                        {
                            return Err(ServiceError::InvalidArgument(
                                "network symbols are not supported".into(),
                            ));
                        }
                        SymbolAction::Load {
                            base: address(&base.ok_or_else(|| required("base"))?)?,
                            pdb: path,
                        }
                    }
                    "lookup" => SymbolAction::Lookup {
                        address: address(&a.ok_or_else(|| required("address"))?)?,
                    },
                    _ => {
                        return Err(ServiceError::InvalidArgument(
                            "symbol action: load/lookup".into(),
                        ))
                    }
                };
                self.command(&session, Command::Symbols(action))
            }
        }
    }
    fn check_evidence_export(&self) -> Result<(), ServiceError> {
        if !self.project_writes {
            return Err(ServiceError::InvalidArgument(
                "evidence export requires separate --enable-writes permission".into(),
            ));
        }
        Ok(())
    }
    fn export_evidence(
        &self,
        value: Value,
        destination: &std::path::Path,
    ) -> Result<Value, ServiceError> {
        use std::io::Write;
        self.check_evidence_export()?;
        let destination = self.policy.allow_write(destination)?;
        if destination.exists() {
            return Err(ServiceError::InvalidArgument(
                "evidence export never overwrites an existing file".into(),
            ));
        }
        let bytes =
            serde_json::to_vec_pretty(&value).map_err(|e| ServiceError::Io(e.to_string()))?;
        if bytes.len() > 32 * 1024 * 1024 {
            return Err(ServiceError::LimitExceeded(
                "serialized evidence exceeds32MiB".into(),
            ));
        }
        let mut file = tempfile::NamedTempFile::new_in(destination.parent().unwrap())
            .map_err(|e| ServiceError::Io(e.to_string()))?;
        file.write_all(&bytes)
            .and_then(|_| file.as_file().sync_all())
            .map_err(|e| ServiceError::Io(e.to_string()))?;
        file.persist_noclobber(&destination)
            .map_err(|e| ServiceError::Io(e.to_string()))?;
        Ok(
            json!({"destination":destination,"bytes":bytes.len(),"sha256":ura_core::sha256_hex(&bytes),"format":value["format"]}),
        )
    }
}
