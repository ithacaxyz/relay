use clap::{Parser, Subcommand};
use eyre::Result;

mod send;

/// Recast - Ithaca relay CLI tool
#[derive(Debug, Parser)]
#[command(name = "recast")]
#[command(about = "CLI tool for interacting with the Ithaca relay")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Send tokens using the Ithaca relay
    Send(send::Args),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Send(args) => send::execute(args).await,
    }
}
