use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

pub const MAX_EVENTS: usize = 256;
pub const MAX_MEMORY: usize = 64 * 1024;
pub const MAX_BREAKPOINTS: usize = 1024;
pub fn hex(a: u64) -> String {
    format!("0x{a:X}")
}

#[derive(Debug, Clone, thiserror::Error, Serialize)]
#[error("{message}")]
pub struct DebugError {
    pub code: String,
    pub message: String,
}
impl DebugError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}
pub type Result<T> = std::result::Result<T, DebugError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum State {
    #[default]
    Idle,
    Launching,
    Attaching,
    Running,
    Paused,
    Stepping,
    Detaching,
    Terminating,
    Exited,
    Detached,
    Failed,
}
impl State {
    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Launching
                | Self::Attaching
                | Self::Running
                | Self::Paused
                | Self::Stepping
                | Self::Detaching
                | Self::Terminating
        )
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LaunchConfig {
    pub executable: PathBuf,
    #[serde(default)]
    pub expected_sha256: Option<String>,
    #[serde(default)]
    pub arguments: Vec<String>,
    pub working_directory: Option<PathBuf>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    #[serde(default = "yes")]
    pub break_at_entry: bool,
}
fn yes() -> bool {
    true
}

#[derive(Debug, Clone)]
pub enum Command {
    Launch(LaunchConfig),
    Attach {
        pid: u32,
        executable: PathBuf,
        expected_sha256: Option<String>,
    },
    Continue {
        pass_exception: bool,
    },
    Pause,
    Step {
        over: bool,
    },
    Detach,
    Terminate,
    Registers {
        thread: Option<u32>,
    },
    Memory {
        address: u64,
        length: usize,
    },
    Stack {
        thread: Option<u32>,
        limit: usize,
    },
    Disassembly {
        address: u64,
        count: usize,
    },
    Breakpoint {
        action: String,
        address: Option<u64>,
        id: Option<u64>,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    pub sequence: u64,
    pub elapsed_micros: u64,
    pub thread: u32,
    pub kind: String,
    pub message: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Thread {
    pub id: u32,
    pub start_address: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Module {
    pub base: String,
    pub size: u64,
    pub path: Option<String>,
    pub sha256: Option<String>,
    pub preferred_base: Option<String>,
    #[serde(default)]
    pub entry_point: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Breakpoint {
    pub id: u64,
    pub session: String,
    pub address: String,
    pub enabled: bool,
    pub original_byte: u8,
    pub hits: u64,
    pub owner: String,
    pub armed: bool,
    pub module: Option<String>,
    pub rva: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Registers {
    pub thread: u32,
    pub architecture: String,
    pub values: BTreeMap<String, String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub schema_version: u32,
    pub session: Option<String>,
    pub state: State,
    pub pid: Option<u32>,
    pub executable: Option<String>,
    pub attached: bool,
    pub selected_thread: Option<u32>,
    pub reason: Option<String>,
    pub exception_code: Option<String>,
    pub first_chance: Option<bool>,
    pub exit_code: Option<u32>,
    pub threads: Vec<Thread>,
    pub modules: Vec<Module>,
    pub breakpoints: Vec<Breakpoint>,
    pub registers: Option<Registers>,
    pub events: Vec<Event>,
    pub events_dropped: u64,
}
