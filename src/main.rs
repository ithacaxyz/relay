//! # Odyssey Relay
//!
//! A relay service that sponsors transactions for EIP-7702 accounts.
use clap::Parser;
use relay::cli::*;

#[tokio::main]
async fn main() {
    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    let args = Args::parse();
    if let Err(err) = args.run().await {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
