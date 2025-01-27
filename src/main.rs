//! # Odyssey Relay
//!
//! A relay service that sponsors transactions for EIP-7702 accounts.
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod error;
mod metrics;
mod rpc;
mod serde;
mod signer;
mod types;
mod upstream;

use crate::rpc::Relay;
use alloy::{
    primitives::Address,
    providers::{network::EthereumWallet, ProviderBuilder},
    rpc::client::RpcClient,
    signers::local::PrivateKeySigner,
};
use clap::Parser;
use eyre::Context;
use http::HeaderName;
use jsonrpsee::server::{RpcServiceBuilder, Server};
use metrics::{build_exporter, MetricsService, RpcMetricsService};
use rpc::RelayApiServer;
use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};
use tower::{layer::layer_fn, ServiceBuilder};
use tower_http::cors::{AllowMethods, AllowOrigin, CorsLayer};
use tracing::{info, level_filters::LevelFilter};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use upstream::Upstream;
use url::Url;

/// The Odyssey relayer service sponsors transactions for EIP-7702 accounts.
#[derive(Debug, Parser)]
#[command(author, about = "Relay", long_about = None)]
struct Args {
    /// The address to serve the RPC on.
    #[arg(long = "http.addr", value_name = "ADDR", default_value_t = IpAddr::V4(Ipv4Addr::LOCALHOST))]
    address: IpAddr,
    /// The port to serve the RPC on.
    #[arg(long = "http.port", value_name = "PORT", default_value_t = 9119)]
    port: u16,
    /// The RPC endpoint of the chain to send transactions to.
    /// Must be a valid HTTP or HTTPS URL pointing to an Ethereum JSON-RPC endpoint.
    #[arg(long, value_name = "RPC_ENDPOINT")]
    upstream: Url,
    /// The address of the entrypoint contract.
    #[arg(long, value_name = "ADDRESS")]
    entrypoint: Address,
    /// The lifetime of a fee quote.
    #[arg(long, value_name = "SECONDS", value_parser = parse_duration_secs, default_value = "5")]
    quote_ttl: Duration,
    /// The secret key to sign fee quotes with.
    #[arg(long, value_name = "SECRET_KEY", env = "RELAY_FEE_SK")]
    quote_secret_key: String,
    /// A fee token the relay accepts.
    #[arg(long = "fee-token", value_name = "ADDRESS", required = true)]
    fee_tokens: Vec<Address>,
    /// The secret key to sign transactions with.
    #[arg(long, value_name = "SECRET_KEY", env = "RELAY_SK")]
    secret_key: String,
}

impl Args {
    /// Run the relayer service.
    async fn run(self) -> eyre::Result<()> {
        tracing_subscriber::registry()
            .with(fmt::layer())
            .with(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .from_env_lossy(),
            )
            .init();

        // setup metrics
        let handle = build_exporter();

        // construct provider
        let signer: PrivateKeySigner =
            self.secret_key.parse().wrap_err("invalid tx signing key")?;
        let wallet = EthereumWallet::from(signer);
        let rpc_client = RpcClient::new_http(self.upstream.clone()).boxed();
        let provider =
            ProviderBuilder::new().with_recommended_fillers().wallet(wallet).on_client(rpc_client);

        // construct quote signer
        let quote_signer: PrivateKeySigner =
            self.quote_secret_key.parse().wrap_err("invalid quote signing key")?;

        // construct rpc module
        let upstream = Upstream::new(provider, self.entrypoint);
        let address = upstream.default_signer_address();
        let rpc = Relay::new(upstream, quote_signer, self.fee_tokens).into_rpc();

        // launch period metric collectors
        metrics::spawn_periodic_collectors(address, vec![self.upstream]).await?;

        // http layers
        let cors = CorsLayer::new()
            .allow_methods(AllowMethods::any())
            .allow_origin(AllowOrigin::any())
            .allow_headers([HeaderName::from_static("content-type")]);
        let metrics = layer_fn(move |service| MetricsService::new(service, handle.clone()));

        // start server
        let server = Server::builder()
            .http_only()
            .set_http_middleware(ServiceBuilder::new().layer(cors).layer(metrics))
            .set_rpc_middleware(RpcServiceBuilder::new().layer_fn(RpcMetricsService::new))
            .build((self.address, self.port))
            .await?;
        info!(addr = %server.local_addr().unwrap(), "Started relay service");

        let handle = server.start(rpc);
        handle.stopped().await;

        Ok(())
    }
}

/// Parses a string representing seconds to a [`Duration`].
fn parse_duration_secs(arg: &str) -> Result<std::time::Duration, std::num::ParseIntError> {
    let seconds = arg.parse()?;
    Ok(std::time::Duration::from_secs(seconds))
}

#[doc(hidden)]
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
