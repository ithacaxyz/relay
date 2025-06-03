//! # Relay CLI
use crate::{
    config::RelayConfig,
    constants::{
        DEFAULT_MAX_TRANSACTIONS, DEFAULT_NUM_SIGNERS, DEFAULT_RPC_DEFAULT_MAX_CONNECTIONS,
        INTENT_GAS_BUFFER, TX_GAS_BUFFER,
    },
    spawn::try_spawn_with_args,
};
use alloy::{
    primitives::Address,
    providers::utils::EIP1559_FEE_ESTIMATION_REWARD_PERCENTILE,
    signers::local::coins_bip39::{English, Mnemonic},
};
use alloy_chains::Chain;
use clap::Parser;
use eyre::OptionExt;
use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    time::Duration,
};
use url::Url;

/// The Ithaca relayer service sponsors transactions for EIP-7702 accounts.
#[derive(Debug, Parser)]
#[command(author, about = "Relay", long_about = None)]
pub struct Args {
    /// The configuration file.
    ///
    /// If missing, a default one will be used and stored in the working directory under
    /// `relay.yaml`.
    #[arg(long, value_name = "CONFIG", env = "RELAY_CONFIG", default_value = "relay.yaml")]
    pub config: PathBuf,
    /// The coin registry file. Maps chain ids and token addresses to coins (eg. ETH, USDC, USDT).
    ///
    /// If missing, a default one will be used and stored in the working directory under
    /// `registry.yaml`.
    #[arg(long, value_name = "REGISTRY", env = "REGISTRY", default_value = "registry.yaml")]
    pub registry: PathBuf,
    /// The address to serve the RPC on.
    #[arg(long = "http.addr", value_name = "ADDR", default_value_t = IpAddr::V4(Ipv4Addr::LOCALHOST))]
    pub address: IpAddr,
    /// The port to serve the RPC on.
    #[arg(long = "http.port", value_name = "PORT", default_value_t = 9119)]
    pub port: u16,
    /// The port to serve the metrics on.
    #[arg(long = "http.metrics-port", value_name = "PORT", default_value_t = 9000)]
    pub metrics_port: u16,
    /// The address of the orchestrator.
    #[arg(
        long = "orchestrator",
        required_unless_present("config_only"),
        value_name = "ORCHESTRATOR"
    )]
    pub orchestrator: Option<Address>,
    /// The address of the delegation proxy.
    #[arg(
        long = "delegation-proxy",
        required_unless_present("config_only"),
        value_name = "DELEGATION"
    )]
    pub delegation_proxy: Option<Address>,
    /// The address of the simulator
    #[arg(long = "simulator", required_unless_present("config_only"), value_name = "SIMULATOR")]
    pub simulator: Option<Address>,
    /// The RPC endpoint of a chain to send transactions to.
    ///
    /// Must be a valid HTTP or HTTPS URL pointing to an Ethereum JSON-RPC endpoint.
    #[arg(long = "endpoint", required_unless_present("config_only"), value_name = "RPC_ENDPOINT")]
    pub endpoints: Option<Vec<Url>>,
    /// The fee recipient address.
    ///
    /// Defaults to the zero address, which means the fees will be accrued by the orchestrator
    /// contract.
    #[arg(long = "fee-recipient", value_name = "ADDRESS", default_value_t = Address::ZERO)]
    pub fee_recipient: Address,
    /// The lifetime of a fee quote.
    #[arg(long, value_name = "SECONDS", value_parser = parse_duration_secs, default_value = "5")]
    pub quote_ttl: Duration,
    /// The lifetime of a token price rate.
    #[arg(long, value_name = "SECONDS", value_parser = parse_duration_secs, default_value = "300")]
    pub rate_ttl: Duration,
    /// Extra buffer added to Intent gas estimates.
    #[arg(long, value_name = "INTENT_GAS", default_value_t = INTENT_GAS_BUFFER)]
    pub intent_gas_buffer: u64,
    /// Extra buffer added to transaction gas estimates.
    #[arg(long, value_name = "TX_OP_GAS", default_value_t = TX_GAS_BUFFER)]
    pub tx_gas_buffer: u64,
    /// A fee token the relay accepts.
    #[arg(long = "fee-token", required_unless_present("config_only"), value_name = "ADDRESS")]
    pub fee_tokens: Option<Vec<Address>>,
    /// The database URL for the relay.
    #[arg(long = "database-url", value_name = "URL", env = "RELAY_DB_URL")]
    pub database_url: Option<String>,
    /// The maximum number of concurrent connections the relay can handle.
    #[arg(long = "max-connections", value_name = "NUM", default_value_t = DEFAULT_RPC_DEFAULT_MAX_CONNECTIONS)]
    pub max_connections: u32,
    /// The maximum number of pending transactions that can be processed by transaction service
    /// simultaneously.
    #[arg(long = "max-pending-transactions", value_name = "NUM", default_value_t = DEFAULT_MAX_TRANSACTIONS)]
    pub max_pending_transactions: usize,
    /// The mnemonic to use for deriving transaction signers.
    #[arg(long = "signers-mnemonic", value_name = "MNEMONIC", env = "RELAY_MNEMONIC")]
    pub signers_mnemonic: Mnemonic<English>,
    /// The number of signers to derive from mnemonic and use to send transactions.
    #[arg(long = "num-signers", value_name = "NUM", default_value_t = DEFAULT_NUM_SIGNERS)]
    pub num_signers: usize,
    /// The RPC endpoints of the sequencers for OP rollups.
    #[arg(long = "sequencer-endpoint", value_name = "RPC_ENDPOINT", value_parser = parse_chain_url)]
    pub sequencer_endpoints: Vec<(Chain, Url)>,
    /// The RPC endpoints of the public nodes for OP rollups.
    #[arg(long = "public-node-endpoint", value_name = "RPC_ENDPOINT", value_parser = parse_chain_url)]
    pub public_node_endpoints: Vec<(Chain, Url)>,
    /// Percentile of the priority fees to use for the transactions.
    ///
    /// Default value is `20.0` which means that priority fee for transactions will be chosen as
    /// 20th percentile of the priority fees of transactions in latest blocks.
    #[arg(long = "priority-fee-percentile", value_name = "PERCENTILE", default_value_t = EIP1559_FEE_ESTIMATION_REWARD_PERCENTILE)]
    pub priority_fee_percentile: f64,
    /// Reads all values from the config file.
    ///
    /// This makes required CLI args not required, but it is important that any required CLI args
    /// have been configured in the config and do not use default values, as this is likely not
    /// what you want.
    #[arg(long = "config-only", default_value_t = false)]
    pub config_only: bool,
    /// The base URL for the Banxa API.
    #[arg(
        long = "banxa-api-url",
        value_name = "URL",
        default_value = "https://api.banxa-sandbox.com",
        env = "BANXA_API_URL"
    )]
    pub banxa_api_url: Url,
    /// The API key for Banxa.
    #[arg(long = "banxa-api-key", value_name = "KEY", env = "BANXA_API_KEY")]
    pub banxa_api_key: Option<String>,
}

impl Args {
    /// Run the relayer service.
    pub async fn run(self) -> eyre::Result<()> {
        let config_path = self.config.clone();
        let registry_path = self.registry.clone();
        try_spawn_with_args(self, &config_path, &registry_path).await?.server.stopped().await;

        Ok(())
    }

    /// Merges [`Args`] values into an existing [`RelayConfig`] instance.
    pub fn merge_relay_config(self, config: RelayConfig) -> RelayConfig {
        config
            .with_signers_mnemonic(self.signers_mnemonic)
            .with_endpoints(&self.endpoints.unwrap_or_default())
            .with_sequencer_endpoints(self.sequencer_endpoints.clone())
            .with_public_node_endpoints(self.public_node_endpoints.clone())
            .with_fee_tokens(&self.fee_tokens.unwrap_or_default())
            .with_fee_recipient(self.fee_recipient)
            .with_address(self.address)
            .with_port(self.port)
            .with_metrics_port(self.metrics_port)
            .with_max_connections(self.max_connections)
            .with_quote_ttl(self.quote_ttl)
            .with_rate_ttl(self.rate_ttl)
            .with_orchestrator(self.orchestrator)
            .with_delegation_proxy(self.delegation_proxy)
            .with_simulator(self.simulator)
            .with_intent_gas_buffer(self.intent_gas_buffer)
            .with_tx_gas_buffer(self.tx_gas_buffer)
            .with_database_url(self.database_url)
            .with_max_pending_transactions(self.max_pending_transactions)
            .with_num_signers(self.num_signers)
            .with_priority_fee_percentile(self.priority_fee_percentile)
            .with_banxa_api_url(self.banxa_api_url)
            .with_banxa_api_key(self.banxa_api_key.unwrap_or_default())
    }
}

/// Parses a string representing seconds to a [`Duration`].
fn parse_duration_secs(arg: &str) -> Result<std::time::Duration, std::num::ParseIntError> {
    let seconds = arg.parse()?;
    Ok(std::time::Duration::from_secs(seconds))
}

/// Parses a string representing a pair of chain id and a url in a format of "chain_id:url".
fn parse_chain_url(arg: &str) -> eyre::Result<(Chain, Url)> {
    let (chain_id, url) = arg.split_once(':').ok_or_eyre("expected chain_id:url argument")?;

    Ok((chain_id.parse()?, url.parse()?))
}
