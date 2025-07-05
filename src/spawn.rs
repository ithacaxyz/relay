//! Relay spawn utilities.
use crate::{
    asset::AssetInfoService,
    chains::Chains,
    cli::Args,
    config::RelayConfig,
    constants::DEFAULT_POLL_INTERVAL,
    metrics::{self, RpcMetricsService, TraceLayer},
    price::{PriceFetcher, PriceOracle, PriceOracleConfig},
    rpc::{AccountApiServer, AccountRpc, Onramp, OnrampApiServer, Relay, RelayApiServer},
    signers::DynSigner,
    storage::RelayStorage,
    transport::{SequencerLayer, create_transport},
    types::{CoinKind, CoinPair, CoinRegistry, FeeTokens, VersionedContracts},
    version::RELAY_LONG_VERSION,
};
use ::metrics::counter;
use alloy::{
    network::Ethereum,
    primitives::B256,
    providers::{DynProvider, Provider, ProviderBuilder, RootProvider},
    rpc::client::{BuiltInConnectionString, ClientBuilder},
    signers::local::LocalSigner,
    transports::layers::RetryBackoffLayer,
};
use alloy_chains::Chain;
use http::header;
use itertools::Itertools;
use jsonrpsee::server::{
    Server, ServerConfig, ServerHandle,
    middleware::{http::ProxyGetRequestLayer, rpc::RpcServiceBuilder},
};
use metrics_exporter_prometheus::PrometheusHandle;
use resend_rs::Resend;
use sqlx::PgPool;
use std::{net::SocketAddr, path::Path, str::FromStr, sync::Arc};
use tower::ServiceBuilder;
use tower_http::cors::{AllowMethods, AllowOrigin, CorsLayer};
use tracing::{info, warn};

/// [`RetryBackoffLayer`] used for chain providers.
///
/// We are allowing max 10 retries with a backoff of 800ms. The CU/s is set to max value to avoid
/// any throttling.
pub const RETRY_LAYER: RetryBackoffLayer = RetryBackoffLayer::new(10, 800, u64::MAX);

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
    /// Price oracle.
    pub price_oracle: PriceOracle,
}

impl RelayHandle {
    /// Returns the url to the http server
    pub fn http_url(&self) -> String {
        format!("http://{}", self.local_addr)
    }
}

/// Attempts to spawn the relay service using CLI arguments and a configuration file.
pub async fn try_spawn_with_args(
    args: Args,
    config_path: &Path,
    registry_path: &Path,
) -> eyre::Result<RelayHandle> {
    let config = if !config_path.exists() {
        let config = args.merge_relay_config(RelayConfig::default());
        config.save_to_file(config_path)?;
        config
    } else if !args.config_only {
        // File exists: load and override with CLI values.
        args.merge_relay_config(RelayConfig::load_from_file(config_path)?)
    } else {
        let mut config = RelayConfig::load_from_file(config_path)?;
        config.secrets.signers_mnemonic = std::env::var("RELAY_MNEMONIC")?.parse()?;
        config.secrets.funder_key = std::env::var("RELAY_FUNDER_KEY")?;
        config.database_url = std::env::var("RELAY_DB_URL").ok();
        config.with_resend_api_key(std::env::var("RESEND_API_KEY").ok())
    };

    let registry = if !registry_path.exists() {
        let registry = CoinRegistry::default();
        registry.save_to_file(registry_path)?;
        registry
    } else {
        CoinRegistry::load_from_file(registry_path)?
    };

    try_spawn(config, registry).await
}

/// Spawns the relay service using the provided [`RelayConfig`] and [`CoinRegistry`].
pub async fn try_spawn(config: RelayConfig, registry: CoinRegistry) -> eyre::Result<RelayHandle> {
    let registry = Arc::new(registry);

    // construct db
    let storage = if let Some(ref db_url) = config.database_url {
        info!("Using PostgreSQL as storage.");
        let pool = PgPool::connect(db_url).await?;
        sqlx::migrate!().run(&pool).await?;

        RelayStorage::pg(pool)
    } else {
        info!("Using in-memory storage.");
        RelayStorage::in_memory()
    };

    // setup signers
    let signers = DynSigner::derive_from_mnemonic(
        config.secrets.signers_mnemonic.clone(),
        config.transactions.num_signers,
    )?;
    let signer_addresses = signers.iter().map(|signer| signer.address()).collect::<Vec<_>>();

    // setup funder signer
    let funder_signer = DynSigner::from_raw(&config.secrets.funder_key).await?;

    // setup providers
    let providers: Vec<DynProvider> = futures_util::future::try_join_all(
        config.chain.endpoints.iter().cloned().map(async |url| {
            let chain_id =
                RootProvider::<Ethereum>::connect(url.as_str()).await?.get_chain_id().await?;

            let (transport, is_local) = create_transport(&url).await?;

            let builder = ClientBuilder::default().layer(TraceLayer).layer(RETRY_LAYER.clone());

            let client = if let Some(sequencer_url) =
                config.chain.sequencer_endpoints.get(&Chain::from_id(chain_id))
            {
                let sequencer = BuiltInConnectionString::from_str(sequencer_url.as_str())?
                    .connect_boxed()
                    .await?;

                info!("Configured sequencer forwarding for chain {chain_id}");

                builder.layer(SequencerLayer::new(sequencer)).transport(transport, is_local)
            } else {
                builder.transport(transport, is_local)
            };

            eyre::Ok(
                ProviderBuilder::new()
                    .connect_client(client.with_poll_interval(DEFAULT_POLL_INTERVAL))
                    .erased(),
            )
        }),
    )
    .await?;

    // setup metrics exporter and periodic metric collectors
    let metrics =
        metrics::setup_exporter((config.server.address, config.server.metrics_port)).await;
    metrics::spawn_periodic_collectors(
        signer_addresses.clone(),
        providers.clone(),
        config.chain.endpoints.clone(),
    )
    .await?;

    // construct quote signer
    let quote_signer = DynSigner(Arc::new(LocalSigner::from_bytes(&B256::random())?));
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
            &CoinPair::ethereum_pairs(&[CoinKind::USDT, CoinKind::USDC]),
        );
    }

    let chains = Chains::new(providers.clone(), signers, storage.clone(), &config).await?;

    // construct asset info service
    let asset_info = AssetInfoService::new(512);
    let asset_info_handle = asset_info.handle();
    tokio::spawn(asset_info);

    // get contract versions from chain.
    let contracts =
        VersionedContracts::new(&config, providers.first().expect("should have at least one"))
            .await?;

    // todo: avoid all this darn cloning
    let relay = Relay::new(
        contracts,
        chains.clone(),
        quote_signer,
        funder_signer.clone(),
        config.quote,
        price_oracle.clone(),
        FeeTokens::new(
            &registry,
            &config.chain.fee_tokens,
            &config.chain.interop_tokens,
            providers,
        )
        .await?,
        config.chain.fee_recipient,
        storage.clone(),
        asset_info_handle,
        config.transactions.priority_fee_percentile,
    );
    let onramp = Onramp::new(config.onramp.clone()).into_rpc();
    let account_rpc = config.email.resend_api_key.as_ref().map(|resend_api_key| {
        AccountRpc::new(
            relay.clone(),
            Resend::new(resend_api_key),
            storage.clone(),
            config.email.porto_base_url.unwrap_or("id.porto.sh".to_string()),
        )
        .into_rpc()
    });
    let mut rpc = relay.into_rpc();

    // http layers
    let cors = CorsLayer::new()
        .allow_methods(AllowMethods::any())
        .allow_origin(AllowOrigin::any())
        .allow_headers([header::CONTENT_TYPE]);

    // start server
    let server = Server::builder()
        .set_config(
            ServerConfig::builder()
                .http_only()
                .max_connections(config.server.max_connections)
                .build(),
        )
        .set_http_middleware(
            ServiceBuilder::new()
                .layer(cors)
                .layer(ProxyGetRequestLayer::new([("/health", "health")])?),
        )
        .set_rpc_middleware(RpcServiceBuilder::new().layer_fn(RpcMetricsService::new))
        .build((config.server.address, config.server.port))
        .await?;
    let addr = server.local_addr()?;
    info!(%addr, "Started relay service");
    info!("Transaction signers: {}", signer_addresses.iter().join(", "));
    info!("Quote signer key: {}", quote_signer_addr);
    info!("Funder signer key: {}", funder_signer.address());

    // version and other information as a metric
    counter!(
        "relay.info",
        "version" => RELAY_LONG_VERSION,
        "orchestrator" => config.orchestrator.to_string(),
        "delegation_proxy" => config.delegation_proxy.to_string(),
        "simulator" => config.simulator.to_string(),
        "funder" => config.funder.to_string(),
        "fee_recipient" => config.chain.fee_recipient.to_string()
    )
    .absolute(1);

    rpc.merge(onramp).expect("could not merge rpc modules");
    if let Some(account_rpc) = account_rpc {
        rpc.merge(account_rpc).expect("could not merge rpc modules");
    } else {
        warn!("No e-mail provider configured.");
    }

    Ok(RelayHandle {
        local_addr: addr,
        server: server.start(rpc),
        chains,
        storage,
        metrics,
        price_oracle,
    })
}
