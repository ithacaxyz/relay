//! Relay spawn utilities.
use crate::{
    chains::Chains,
    cli::Args,
    config::RelayConfig,
    metrics::{self, RpcMetricsService},
    price::{PriceFetcher, PriceOracle},
    rpc::{Relay, RelayApiServer},
    signers::DynSigner,
    storage::RelayStorage,
    types::{CoinKind, CoinPair, CoinRegistry, FeeTokens},
};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use http::header;
use itertools::Itertools;
use jsonrpsee::server::{RpcServiceBuilder, Server, ServerHandle};
use std::{path::Path, sync::Arc};
use tower::ServiceBuilder;
use tower_http::cors::{AllowMethods, AllowOrigin, CorsLayer};
use tracing::{info, warn};

/// Attempts to spawn the relay service using CLI arguments and a configuration file.
pub async fn try_spawn_with_args<P: AsRef<Path>>(
    args: Args,
    config_path: P,
    registry_path: P,
) -> eyre::Result<ServerHandle> {
    let config = if !config_path.as_ref().exists() {
        let config = args.merge_relay_config(RelayConfig::default());
        config.save_to_file(&config_path)?;
        config
    } else {
        // File exists: load and override with CLI values.
        args.merge_relay_config(RelayConfig::load_from_file(&config_path)?)
    };

    let registry = if !registry_path.as_ref().exists() {
        let registry = CoinRegistry::default();
        registry.save_to_file(&registry_path)?;
        registry
    } else {
        CoinRegistry::load_from_file(&registry_path)?
    };

    try_spawn(config, registry).await
}

/// Spawns the relay service using the provided [`RelayConfig`] and [`CoinRegistry`].
pub async fn try_spawn(config: RelayConfig, registry: CoinRegistry) -> eyre::Result<ServerHandle> {
    let registry = Arc::new(registry);

    // construct provider
    let signers = futures_util::future::try_join_all(
        config.secrets.transaction_keys.iter().map(|sk| DynSigner::load(sk, None)),
    )
    .await?;
    let signer_addresses = signers.iter().map(|signer| signer.address()).collect::<Vec<_>>();

    let providers: Vec<DynProvider> = config
        .chain
        .endpoints
        .iter()
        .cloned()
        .map(|url| ProviderBuilder::new().on_http(url).erased())
        .collect();

    // construct quote signer
    let quote_signer = DynSigner::load(&config.secrets.quote_key, None).await?;
    let quote_signer_addr = quote_signer.address();

    // construct rpc module
    let mut price_oracle = PriceOracle::new();
    if let Some(constant_rate) = config.quote.constant_rate {
        warn!("Setting a constant price rate: {constant_rate}. Should not be used in production!");
        price_oracle = price_oracle.with_constant_rate(constant_rate);
    } else {
        price_oracle.spawn_fetcher(
            registry.clone(),
            PriceFetcher::CoinGecko,
            &CoinPair::ethereum_pairs(&[CoinKind::USDT]),
        );
    }

    let storage = RelayStorage::in_memory();

    // todo: avoid all this darn cloning
    let rpc = Relay::new(
        Chains::new(providers.clone(), signers, storage.clone()).await?,
        quote_signer,
        config.quote,
        price_oracle,
        FeeTokens::new(&registry, &config.chain.fee_tokens, providers).await?,
        storage.clone(),
    )
    .into_rpc();

    // setup metrics exporter and periodic metric collectors
    metrics::setup_exporter((config.server.address, config.server.metrics_port)).await;
    metrics::spawn_periodic_collectors(signer_addresses.clone(), config.chain.endpoints).await?;

    // http layers
    let cors = CorsLayer::new()
        .allow_methods(AllowMethods::any())
        .allow_origin(AllowOrigin::any())
        .allow_headers([header::CONTENT_TYPE]);

    // start server
    let server = Server::builder()
        .http_only()
        .set_http_middleware(ServiceBuilder::new().layer(cors))
        .set_rpc_middleware(RpcServiceBuilder::new().layer_fn(RpcMetricsService::new))
        .build((config.server.address, config.server.port))
        .await?;
    info!(addr = %server.local_addr().unwrap(), "Started relay service");
    info!("Transaction signers: {}", signer_addresses.iter().join(", "));
    info!("Quote signer key: {}", quote_signer_addr);

    Ok(server.start(rpc))
}
