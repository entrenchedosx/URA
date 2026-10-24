//! Versioned trusted Python extensions. Worker containment is not an OS sandbox.
mod batch;
mod bridge;
mod extensionpoints;
pub mod options;
pub mod plugins;
mod process;
pub mod runtime;
mod worker;
pub use worker::{ExecutionConfig, ExtensionHost, Limits};
pub type Result<T> = std::result::Result<T, String>;
pub(crate) fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(message.into())
}
pub(crate) fn bounded(value: serde_json::Value) -> Result<serde_json::Value> {
    if serde_json::to_vec(&value).map_err(|e| e.to_string())?.len() > 1024 * 1024 {
        invalid("Extension response exceeds1MiB; request a smaller page")
    } else {
        Ok(value)
    }
}
pub const API_VERSION: u32 = 1;
pub const SDK_VERSION: &str = "1.0.0";
