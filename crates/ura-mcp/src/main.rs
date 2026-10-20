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
                  never executed. The server speaks MCP over stdin/stdout; logs are written to \
                  stderr. Paths must resolve inside an allowed root (--allow, default: the current \
                  directory). Project and export writes stay disabled unless --enable-writes is set."
)]
struct Cli {
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
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(cli.log))
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    let policy = PathPolicy::new(cli.allow)?;
    let service = Service::new(policy, cli.enable_writes);
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
