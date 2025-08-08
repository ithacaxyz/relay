//! # Ithaca Relay
//!
//! A relay service that sponsors transactions for EIP-7702 accounts.

use clap::Parser;
use relay::{
    cli::*,
    otlp::{OtelConfig, OtelGuard},
};
use tracing::debug;
use tracing_subscriber::prelude::*;

fn init_tracing_subscriber() -> Option<OtelGuard> {
    let registry = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_filter(tracing_subscriber::filter::EnvFilter::from_default_env()),
    );

    if let Some(cfg) = OtelConfig::load() {
        let guard = cfg.provider();
        registry.with(guard.layer()).init();
        Some(guard)
    } else {
        registry.init();
        None
    }
}

#[tokio::main]
async fn main() {
    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        unsafe { std::env::set_var("RUST_BACKTRACE", "1") };
    }

    let _guard = init_tracing_subscriber();
    if _guard.is_some() {
        debug!("opentelemetry initialized");
    }

    let args = Args::parse();
    if let Err(err) = args.run().await {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
