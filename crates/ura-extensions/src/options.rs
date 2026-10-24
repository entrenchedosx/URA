//! Startup permissions are chosen locally, never granted by an MCP request.
use crate::{runtime::Runtime, ExecutionConfig, Result};
use std::path::PathBuf;
#[derive(clap::Args, Default)]
pub struct Options {
    /// Run trusted Python code with the user's OS permissions. NOT a sandbox.
    #[arg(long, global = true)]
    pub enable_scripting: bool,
    /// Allow inline code as well as content-pinned --trust-script files.
    #[arg(long, global = true)]
    pub allow_script_snippets: bool,
    /// Explicit local plugin install/enable/disable/uninstall authority.
    #[arg(long, global = true)]
    pub enable_plugin_management: bool,
    /// Pin a trusted script's canonical path and current SHA256 for this process.
    #[arg(long = "trust-script", global = true)]
    pub trust_scripts: Vec<PathBuf>,
    /// Additional host API grant; cannot restrict direct Python OS APIs.
    #[arg(long = "script-capability", global = true)]
    pub script_capabilities: Vec<String>,
    #[arg(long, global = true)]
    pub extensions_dir: Option<PathBuf>,
    /// Complete locked CPython runtime folder (no system Python discovery).
    #[arg(long, global = true)]
    pub python_runtime: Option<PathBuf>,
}
impl Options {
    pub fn configuration(self) -> Result<ExecutionConfig> {
        let mut c = ExecutionConfig {
            enabled: self.enable_scripting,
            snippets: self.allow_script_snippets,
            plugin_management: self.enable_plugin_management,
            ..Default::default()
        };
        if let Some(root) = self.extensions_dir {
            c.registry = root;
        }
        if let Some(path) = self.python_runtime {
            c.runtime = Some(Runtime::new(&path)?);
        }
        c.capabilities.extend(self.script_capabilities);
        for path in self.trust_scripts {
            c.trust_script(&path)?;
        }
        Ok(c)
    }
}
