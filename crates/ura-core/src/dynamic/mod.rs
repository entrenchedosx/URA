//! Isolated machine execution and imported observed evidence. No OS execution.
pub mod cpu;
pub mod image;
pub mod memory;
pub mod replay;
use crate::ir::Address;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Fault {
    pub kind: String,
    pub message: String,
    pub address: Address,
}
impl Fault {
    pub fn new(kind: &str, address: u64, message: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            message: message.into(),
            address: Address(address),
        }
    }
}
impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} at {}: {}", self.kind, self.address, self.message)
    }
}
pub type Result<T> = std::result::Result<T, Fault>;
