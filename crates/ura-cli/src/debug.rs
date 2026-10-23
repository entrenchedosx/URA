use clap::Args;
use std::{
    io::{BufRead, Write},
    path::PathBuf,
};
use ura_service::{DebugPermissions, DebugService, ErrorView, PathPolicy, ServiceError};
#[derive(Args, Default)]
pub struct DebugOptions {
    #[arg(long, global = true)]
    pub enable_debug_launch: bool,
    #[arg(long, global = true)]
    pub enable_debug_capture: bool,
    #[arg(long, global = true)]
    pub enable_debug_attach: bool,
    #[arg(long, global = true)]
    pub enable_debug_terminate_attached: bool,
    #[arg(long = "debug-target", global = true)]
    pub targets: Vec<PathBuf>,
    #[arg(long = "debug-pid", global = true)]
    pub pids: Vec<u32>,
}
impl DebugOptions {
    pub fn permissions(self) -> DebugPermissions {
        DebugPermissions {
            launch: self.enable_debug_launch,
            attach: self.enable_debug_attach,
            terminate_attached: self.enable_debug_terminate_attached,
            targets: self.targets,
            attach_pids: self.pids,
        }
    }
}
/// One process owns the session until EOF. No session survives a CLI restart.
pub fn run(policy: PathPolicy, options: DebugOptions, writes: bool) -> Result<(), ServiceError> {
    let capture = options.enable_debug_capture;
    let mut debugger = DebugService::new(policy, options.permissions())?
        .with_project_writes(writes)
        .with_memory_capture(capture);
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut output = std::io::stdout().lock();
    loop {
        let mut line = Vec::new();
        let read = std::io::Read::take(&mut input, 65537)
            .read_until(b'\n', &mut line)
            .map_err(|e| ServiceError::Io(e.to_string()))?;
        if read == 0 {
            break;
        }
        if line.len() > 65536 {
            return Err(ServiceError::LimitExceeded(
                "debug command line exceeds 64KiB; session closed".into(),
            ));
        }
        let result = serde_json::from_slice(&line)
            .map_err(|e| ServiceError::InvalidArgument(e.to_string()))
            .and_then(|v| debugger.rpc(v));
        let response = match result {
            Ok(value) => serde_json::json!({"schemaVersion":1,"result":value}),
            Err(error) => serde_json::to_value(ErrorView::new(&error)).unwrap(),
        };
        writeln!(output, "{response}")
            .and_then(|_| output.flush())
            .map_err(|e| ServiceError::Io(e.to_string()))?;
    }
    Ok(())
}
