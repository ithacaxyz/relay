//! Relay spawn utilities.
use crate::{
    asset::AssetInfoService,
    chains::Chains,
    cli::Args,
    config::RelayConfig,
    constants::ESCROW_REFUND_DURATION_SECS,
    diagnostics::run_diagnostics,
    metrics::{self, RpcMetricsService},
    price::{PriceFetcher, PriceOracle, PriceOracleConfig},
    rpc::{AccountApiServer, AccountRpc, Relay, RelayApiServer},
    signers::DynSigner,
    storage::RelayStorage,
    types::VersionedContracts,
    version::RELAY_LONG_VERSION,
};
use ::metrics::counter;
use alloy::{primitives::B256, signers::local::LocalSigner};
use http::header;
use itertools::Itertools;
use jsonrpsee::server::{
    Server, ServerConfig, ServerHandle,
    middleware::{http::ProxyGetRequestLayer, rpc::RpcServiceBuilder},
};
use metrics_exporter_prometheus::PrometheusHandle;
use resend_rs::Resend;
use sqlx::PgPool;
use std::{net::SocketAddr, path::Path, sync::Arc};
use tower::ServiceBuilder;
use tower_http::cors::{AllowMethods, AllowOrigin, CorsLayer};
use tracing::{info, warn};

/// Context returned once relay is launched.
#[derive(Debug, Clone)]
pub struct RelayHandle {
    /// The socket address to which the server is bound.
    pub local_addr: SocketAddr,
    /// Handle to RPC server.
    pub server: ServerHandle,
    /// Configured providers.
    pub chains: Arc<Chains>,
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
pub async fn try_spawn_with_args(args: Args, config_path: &Path) -> eyre::Result<RelayHandle> {
    let skip_diagnostics = args.skip_diagnostics;
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
        config.secrets.funder_key = std::env::var("RELAY_FUNDER_SIGNER_KEY")?;
        config.secrets.faucet_private_key = std::env::var("FAUCET_PRIVATE_KEY")?;
        config.database_url = std::env::var("RELAY_DB_URL").ok();
        config
            .with_resend_api_key(std::env::var("RESEND_API_KEY").ok())
            .with_simple_settler_owner_key(std::env::var("RELAY_SETTLER_OWNER_KEY").ok())
            .with_funder_owner_key(std::env::var("RELAY_FUNDER_OWNER_KEY").ok())
            .with_binance_keys(
                std::env::var("BINANCE_API_KEY").ok(),
                std::env::var("BINANCE_API_SECRET").ok(),
            )
    };

    try_spawn(config, skip_diagnostics).await
}

/// Spawns the relay service using the provided [`RelayConfig`].
pub async fn try_spawn(config: RelayConfig, skip_diagnostics: bool) -> eyre::Result<RelayHandle> {
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

    // setup metrics exporter and periodic metric collectors
    let metrics =
        metrics::setup_exporter((config.server.address, config.server.metrics_port)).await;

    // setup signers
    let signers = DynSigner::derive_from_mnemonic(
        config.secrets.signers_mnemonic.clone(),
        config.transactions.num_signers,
    )?;
    let signer_addresses = signers.iter().map(|signer| signer.address()).collect::<Vec<_>>();

    // setup funder signer
    let funder_signer = DynSigner::from_raw(&config.secrets.funder_key).await?;

    // setup faucet signer for faucet
    let faucet_signer = DynSigner::from_raw(&config.secrets.faucet_private_key).await?;

    // build chains
    let chains = Arc::new(Chains::new(signers.clone(), storage.clone(), &config).await?);

    // Run pre-flight diagnostics
    if skip_diagnostics {
        warn!("Skipping pre-flight diagnostics.");
    } else {
        info!("Running pre-flight diagnostics.");
        let report = run_diagnostics(&config, chains.clone(), &signers).await?;
        report.log();

        if report.has_errors() {
            eyre::bail!(
                "Pre-flight diagnostics failed with errors. Please fix the issues before starting the relay."
            );
        }
    }

    metrics::spawn_periodic_collectors(signer_addresses.clone(), chains.clone()).await?;

    // construct quote signer
    let quote_signer = DynSigner(Arc::new(LocalSigner::from_bytes(&B256::random())?));
    let quote_signer_addr = quote_signer.address();

    // construct rpc module
    let mut price_oracle = PriceOracle::new(PriceOracleConfig { rate_ttl: config.quote.rate_ttl });
    if let Some(constant_rate) = config.quote.constant_rate {
        warn!("Setting a constant price rate: {constant_rate}. Should not be used in production!");
        price_oracle = price_oracle.with_constant_rate(constant_rate);
    } else {
        price_oracle.spawn_fetcher(PriceFetcher::CoinGecko, &config);
    }

    // construct asset info service
    let asset_info = AssetInfoService::new(512, &config);
    let asset_info_handle = asset_info.handle();
    tokio::spawn(asset_info);

    // get contract versions from chain.
    let contracts = VersionedContracts::new(
        &config,
        chains
            .chains_iter()
            .next()
            .map(|chain| chain.provider())
            .expect("should have at least one"),
    )
    .await?;

    // todo: avoid all this darn cloning
    let relay = Relay::new(
        contracts,
        chains.clone(),
        quote_signer,
        funder_signer.clone(),
        faucet_signer.clone(),
        config.quote,
        price_oracle.clone(),
        config.fee_recipient,
        storage.clone(),
        asset_info_handle,
        config
            .interop
            .as_ref()
            .map(|i| i.escrow_refund_threshold)
            .unwrap_or(ESCROW_REFUND_DURATION_SECS),
    );
    let account_rpc = config.email.resend_api_key.as_ref().map(|resend_api_key| {
        AccountRpc::new(
            relay.clone(),
            Resend::new(resend_api_key),
            storage.clone(),
            config.email.porto_base_url.unwrap_or("id.porto.sh".to_string()),
            config.secrets.service_api_key.clone(),
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
        "fee_recipient" => config.fee_recipient.to_string()
    )
    .absolute(1);

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
