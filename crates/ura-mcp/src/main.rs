mod params;
mod server;

use std::path::PathBuf;

use clap::Parser;
use rmcp::ServiceExt;
use tracing_subscriber::EnvFilter;
use ura_service::{PathPolicy, Service};

use crate::server::UraServer;

#[derive(Parser)]
#[command(
    name = "ura-mcp",
    version,
    about = "URA static analysis MCP server (stdio)",
    long_about = "URA static analysis MCP server. Samples are parsed and analysed locally and are \
                  never executed by static analysis. Debugger execution/attachment require separate explicit flags and exact targets. The server speaks MCP over stdin/stdout; logs are written to \
                  stderr. Paths must resolve inside an allowed root (--allow, default: the current \
                  directory). Project and export writes stay disabled unless --enable-writes is set."
)]
struct Cli {
    /// Permit isolated virtual CPU sessions; does not grant native execution
    #[arg(long)]
    enable_emulation: bool,
    #[arg(long)]
    enable_debug_launch: bool,
    #[arg(long)]
    enable_debug_capture: bool,
    #[arg(long)]
    enable_debug_attach: bool,
    #[arg(long)]
    enable_debug_terminate_attached: bool,
    #[arg(long = "debug-target")]
    debug_targets: Vec<PathBuf>,
    #[arg(long = "debug-pid")]
    debug_pids: Vec<u32>,
    /// Directory that binary, project and export paths must resolve inside (repeatable)
    #[arg(long = "allow", value_name = "DIR")]
    allow: Vec<PathBuf>,
    /// Enable the project write tools (rename, comment, save, export)
    #[arg(long)]
    enable_writes: bool,
    /// stderr log filter (tracing EnvFilter syntax)
    #[arg(long, default_value = "info")]
    log: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if ura_core::symbolic::solver::worker_entry() {
        return Ok(());
    }
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(cli.log))
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    let policy = PathPolicy::new(cli.allow)?;
    let mut service = Service::new(policy.clone(), cli.enable_writes);
    service.dynamic = ura_service::dynamic::DynamicService::new(policy.clone(), cli.enable_writes)
        .with_emulation(cli.enable_emulation);
    service.debugger = ura_service::DebugService::new(
        policy,
        ura_service::DebugPermissions {
            launch: cli.enable_debug_launch,
            attach: cli.enable_debug_attach,
            terminate_attached: cli.enable_debug_terminate_attached,
            targets: cli.debug_targets,
            attach_pids: cli.debug_pids,
        },
    )?
    .with_project_writes(cli.enable_writes)
    .with_memory_capture(cli.enable_debug_capture);
    let server = UraServer::new(service);

    tracing::info!(
        writes = cli.enable_writes,
        "starting URA MCP server on stdio"
    );
    let running = server.serve(rmcp::transport::stdio()).await?;
    let reason = running.waiting().await?;
    tracing::info!(?reason, "URA MCP server stopped");
    Ok(())
}
