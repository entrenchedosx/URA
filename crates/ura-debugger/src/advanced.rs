use crate::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BreakpointKind {
    #[default]
    Software,
    HardwareExecute,
    Write,
    ReadWrite,
}
#[derive(Debug, Clone)]
pub struct BreakpointConfig {
    pub address: u64,
    pub kind: BreakpointKind,
    pub length: u8,
    pub thread: Option<u32>,
    pub condition: Option<String>,
    pub hit_after: u64,
    pub hit_every: u64,
}
impl BreakpointConfig {
    pub fn software(address: u64) -> Self {
        Self {
            address,
            kind: BreakpointKind::Software,
            length: 1,
            thread: None,
            condition: None,
            hit_after: 1,
            hit_every: 1,
        }
    }
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TraceMode {
    #[default]
    Events,
    Instructions,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct TraceConfig {
    pub mode: TraceMode,
    pub max_events: usize,
    pub max_bytes: usize,
    pub max_duration_ms: u64,
    pub max_steps: u64,
    pub registers: bool,
}
impl Default for TraceConfig {
    fn default() -> Self {
        Self {
            mode: TraceMode::Events,
            max_events: 2048,
            max_bytes: 1024 * 1024,
            max_duration_ms: 10000,
            max_steps: 1000,
            registers: true,
        }
    }
}
impl TraceConfig {
    pub fn validate(&self) -> Result<()> {
        if !(1..=10000).contains(&self.max_events)
            || !(1024..=4 * 1024 * 1024).contains(&self.max_bytes)
            || !(1..=60000).contains(&self.max_duration_ms)
            || !(1..=100000).contains(&self.max_steps)
        {
            return Err(DebugError::new(
                "limit",
                "trace limits: 1..10000 events, 1KiB..4MiB, 1..60000ms, 1..100000 steps",
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Clone)]
pub enum TraceAction {
    Start(TraceConfig),
    Stop,
    Clear,
    Read { after: u64, limit: usize },
    Export,
}
#[derive(Debug, Clone)]
pub enum CaptureAction {
    Capture { address: u64, length: usize },
    List,
    Info { id: u64 },
    Remove { id: u64 },
    Compare { id: u64, other: Option<u64> },
    Disassembly { id: u64, address: u64, count: usize },
    Export { id: u64 },
}
#[derive(Debug, Clone)]
pub enum SymbolAction {
    Load { base: u64, pdb: std::path::PathBuf },
    Lookup { address: u64 },
}
