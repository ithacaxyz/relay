//! Relay spawn utilities.
use crate::{
    asset::AssetInfoService,
    chains::Chains,
    cli::Args,
    config::RelayConfig,
    metrics::{self, RpcMetricsService, TraceLayer},
    price::{PriceFetcher, PriceOracle, PriceOracleConfig},
    rpc::{Relay, RelayApiServer},
    signers::DynSigner,
    storage::RelayStorage,
    types::{CoinKind, CoinPair, CoinRegistry, FeeTokens},
};
use alloy::{
    providers::{DynProvider, Provider, ProviderBuilder},
    rpc::client::ClientBuilder,
    transports::layers::RetryBackoffLayer,
};
use http::header;
use itertools::Itertools;
use jsonrpsee::server::{
    RpcServiceBuilder, Server, ServerHandle, middleware::http::ProxyGetRequestLayer,
};
use metrics_exporter_prometheus::PrometheusHandle;
use sqlx::PgPool;
use std::{net::SocketAddr, path::Path, sync::Arc};
use tower::ServiceBuilder;
use tower_http::cors::{AllowMethods, AllowOrigin, CorsLayer};
use tracing::{info, warn};

/// [`RetryBackoffLayer`] used for chain providers.
///
/// We are allowing max 10 retries with a backoff of 800ms. The CU/s is set to max value to avoid
/// any throttling.
const RETRY_LAYER: RetryBackoffLayer = RetryBackoffLayer::new(10, 800, u64::MAX);

/// Context returned once relay is launched.
#[derive(Debug, Clone)]
pub struct RelayHandle {
    /// The socket address to which the server is bound.
    pub local_addr: SocketAddr,
    /// Handle to RPC server.
    pub server: ServerHandle,
    /// Configured providers.
    pub chains: Chains,
    /// Storage of the relay.
    pub storage: RelayStorage,
    /// Metrics collector handle.
    pub metrics: PrometheusHandle,
}

impl RelayHandle {
    /// Returns the url to the http server
    pub fn http_url(&self) -> String {
        format!("http://{}", self.local_addr)
    }
}

/// Attempts to spawn the relay service using CLI arguments and a configuration file.
pub async fn try_spawn_with_args<P: AsRef<Path>>(
    args: Args,
    config_path: P,
    registry_path: P,
) -> eyre::Result<RelayHandle> {
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
pub async fn try_spawn(config: RelayConfig, registry: CoinRegistry) -> eyre::Result<RelayHandle> {
    let registry = Arc::new(registry);

    // construct db
    let storage = if let Some(db_url) = config.database_url {
        info!("Using PostgreSQL as storage.");
        let pool = PgPool::connect(&db_url).await?;
        sqlx::migrate!().run(&pool).await?;

        RelayStorage::pg(pool)
    } else {
        info!("Using in-memory storage.");
        RelayStorage::in_memory()
    };

    // construct provider
    let signers = futures_util::future::try_join_all(
        config.secrets.transaction_keys.iter().map(|sk| DynSigner::load(sk, None)),
    )
    .await?;
    let signer_addresses = signers.iter().map(|signer| signer.address()).collect::<Vec<_>>();

    // setup metrics exporter and periodic metric collectors
    let metrics =
        metrics::setup_exporter((config.server.address, config.server.metrics_port)).await;
    metrics::spawn_periodic_collectors(signer_addresses.clone(), config.chain.endpoints.clone())
        .await?;

    let providers: Vec<DynProvider> = futures_util::future::try_join_all(
        config.chain.endpoints.iter().cloned().map(|url| async move {
            ClientBuilder::default()
                .layer(TraceLayer)
                .layer(RETRY_LAYER.clone())
                .connect(url.as_str())
                .await
                .map(|client| ProviderBuilder::new().on_client(client).erased())
        }),
    )
    .await?;

    // construct quote signer
    let quote_signer = DynSigner::load(&config.secrets.quote_key, None).await?;
    let quote_signer_addr = quote_signer.address();

    // construct rpc module
    let mut price_oracle = PriceOracle::new(PriceOracleConfig { rate_ttl: config.quote.rate_ttl });
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

    let chains =
        Chains::new(providers.clone(), signers, storage.clone(), config.transactions.clone())
            .await?;

    // construct asset info service
    let asset_info = AssetInfoService::new(512);
    let asset_info_handle = asset_info.handle();
    tokio::spawn(asset_info);

    // todo: avoid all this darn cloning
    let rpc = Relay::new(
        config.entrypoint,
        chains.clone(),
        quote_signer,
        config.quote,
        price_oracle,
        FeeTokens::new(&registry, &config.chain.fee_tokens, providers).await?,
        storage.clone(),
        asset_info_handle,
    )
    .into_rpc();

    // http layers
    let cors = CorsLayer::new()
        .allow_methods(AllowMethods::any())
        .allow_origin(AllowOrigin::any())
        .allow_headers([header::CONTENT_TYPE]);

    // start server
    let server = Server::builder()
        .http_only()
        .max_connections(config.server.max_connections)
        .set_http_middleware(
            ServiceBuilder::new()
                .layer(cors)
                .layer(ProxyGetRequestLayer::new("/health", "health")?),
        )
        .set_rpc_middleware(RpcServiceBuilder::new().layer_fn(RpcMetricsService::new))
        .build((config.server.address, config.server.port))
        .await?;
    let addr = server.local_addr()?;
    info!(%addr, "Started relay service");
    info!("Transaction signers: {}", signer_addresses.iter().join(", "));
    info!("Quote signer key: {}", quote_signer_addr);

    Ok(RelayHandle { local_addr: addr, server: server.start(rpc), chains, storage, metrics })
}
