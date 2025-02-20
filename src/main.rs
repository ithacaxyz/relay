//! # Ithaca Relay
//!
//! A relay service that sponsors transactions for EIP-7702 accounts.
use clap::Parser;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use relay::cli::*;
use std::time::Duration;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

/// Builds a Prometheus exporter, returning a handle.
///
/// The recorder will perform upkeep every 5 seconds.
///
/// # Panics
///
/// This will panic if the Prometheus recorder could not be set as the global metrics recorder.
fn build_exporter() -> PrometheusHandle {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();

    let recorder_handle = handle.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            recorder_handle.run_upkeep();
        }
    });

    metrics::set_global_recorder(recorder).expect("could not set metrics recorder");

    handle
}

#[tokio::main]
async fn main() {
    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        unsafe { std::env::set_var("RUST_BACKTRACE", "1") };
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder().with_default_directive(LevelFilter::INFO.into()).from_env_lossy(),
        )
        .init();

    let args = Args::parse();
    if let Err(err) = args.run(Some(build_exporter())).await {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
