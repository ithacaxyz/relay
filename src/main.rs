//! # Odyssey Relay
//!
//! A relay service that sponsors transactions for EIP-7702 accounts.
use alloy::{
    primitives::Address,
    providers::{network::EthereumWallet, ProviderBuilder},
    signers::Signer,
};
use clap::Parser;
use http::header;
use jsonrpsee::server::{RpcServiceBuilder, Server};
use relay::{
    metrics::{build_exporter, MetricsService, RpcMetricsService},
    price::{PriceFetcher, PriceOracle},
    rpc::{Relay, RelayApiServer},
    signer::LocalOrAws,
    types::{CoinKind, CoinPair, FeeTokens},
    upstream::Upstream,
};
use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};
use tower::{layer::layer_fn, ServiceBuilder};
use tower_http::cors::{AllowMethods, AllowOrigin, CorsLayer};
use tracing::{info, level_filters::LevelFilter};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
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
        let signer = LocalOrAws::load(&self.secret_key, None).await?;
        let signer_addr = signer.address();

        let wallet = EthereumWallet::from(signer);
        let provider = ProviderBuilder::new().wallet(wallet).on_http(self.upstream.clone());

        // construct quote signer
        let quote_signer = LocalOrAws::load(&self.quote_secret_key, None).await?;
        let quote_signer_addr = quote_signer.address();

        // construct rpc module
        let upstream = Upstream::new(provider, self.entrypoint).await?;
        let address = upstream.default_signer_address();
        let price_oracle = PriceOracle::new();
        price_oracle
            .spawn_fetcher(PriceFetcher::CoinGecko, &CoinPair::ethereum_pairs(&[CoinKind::USDT]));

        let rpc = Relay::new(
            upstream.clone(),
            quote_signer,
            self.quote_ttl,
            price_oracle,
            FeeTokens::new(&self.fee_tokens, upstream).await?,
        )
        .into_rpc();

        // launch period metric collectors
        relay::metrics::spawn_periodic_collectors(address, vec![self.upstream]).await?;

        // http layers
        let cors = CorsLayer::new()
            .allow_methods(AllowMethods::any())
            .allow_origin(AllowOrigin::any())
            .allow_headers([header::CONTENT_TYPE]);
        let metrics = layer_fn(move |service| MetricsService::new(service, handle.clone()));

        // start server
        let server = Server::builder()
            .http_only()
            .set_http_middleware(ServiceBuilder::new().layer(cors).layer(metrics))
            .set_rpc_middleware(RpcServiceBuilder::new().layer_fn(RpcMetricsService::new))
            .build((self.address, self.port))
            .await?;
        info!(addr = %server.local_addr().unwrap(), "Started relay service");
        info!("Transaction signer key: {}", signer_addr);
        info!("Quote signer key: {}", quote_signer_addr);

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
