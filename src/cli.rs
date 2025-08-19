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
    /// The addresses of legacy delegation proxies.
    #[arg(long = "legacy-delegation-proxy", value_name = "ADDRESS")]
    pub legacy_delegation_proxies: Option<Vec<Address>>,
    /// The address of the simulator
    #[arg(long = "simulator", required_unless_present("config_only"), value_name = "SIMULATOR")]
    pub simulator: Option<Address>,
    /// The address of the funder
    #[arg(long = "funder", required_unless_present("config_only"), value_name = "FUNDER")]
    pub funder: Option<Address>,
    /// The address of the escrow contract
    #[arg(long = "escrow", required_unless_present("config_only"), value_name = "ESCROW")]
    pub escrow: Option<Address>,
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
    /// The constant rate for the price oracle. Used for testing.
    #[arg(long, value_name = "RATE")]
    pub constant_rate: Option<f64>,
    /// Extra buffer added to Intent gas estimates.
    #[arg(long, value_name = "INTENT_GAS", default_value_t = INTENT_GAS_BUFFER)]
    pub intent_gas_buffer: u64,
    /// Extra buffer added to transaction gas estimates.
    #[arg(long, value_name = "TX_OP_GAS", default_value_t = TX_GAS_BUFFER)]
    pub tx_gas_buffer: u64,
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
    // TODO(mattsse): remove
    pub num_signers: usize,
    /// The funder signing key (hex private key or KMS ARN).
    #[arg(
        long = "funder-signing-key",
        required_unless_present("config_only"),
        value_name = "KEY",
        env = "RELAY_FUNDER_SIGNER_KEY"
    )]
    pub funder_key: Option<String>,
    /// The service API key for protected RPC endpoints.
    #[arg(long = "service-api-key", value_name = "KEY", env = "RELAY_SERVICE_API_KEY")]
    pub service_api_key: Option<String>,
    /// The RPC endpoints of the public nodes for OP rollups.
    #[arg(long = "public-node-endpoint", value_name = "RPC_ENDPOINT", value_parser = parse_chain_url)]
    pub public_node_endpoints: Vec<(Chain, Url)>,
    /// Reads all values from the config file.
    ///
    /// This makes required CLI args not required, but it is important that any required CLI args
    /// have been configured in the config and do not use default values, as this is likely not
    /// what you want.
    #[arg(long = "config-only", default_value_t = false)]
    pub config_only: bool,
    /// The API key for Resend.
    #[arg(long = "resend-api-key", value_name = "KEY", env = "RESEND_API_KEY")]
    pub resend_api_key: Option<String>,
    /// The base URL for Porto services.
    #[arg(long = "porto-base-url", value_name = "URL", env = "PORTO_BASE_URL")]
    pub porto_base_url: Option<String>,
    /// The funder owner key for rebalance service.
    #[arg(long = "funder-owner-key", value_name = "KEY", env = "RELAY_FUNDER_OWNER_KEY")]
    pub funder_owner_key: Option<String>,
    /// The API key for Binance.
    #[arg(long = "binance-api-key", value_name = "KEY", env = "BINANCE_API_KEY")]
    pub binance_api_key: Option<String>,
    /// The API secret for Binance.
    #[arg(long = "binance-api-secret", value_name = "KEY", env = "BINANCE_API_SECRET")]
    pub binance_api_secret: Option<String>,
    /// Skip pre-flight diagnostics checks on startup.
    #[arg(long = "skip-diagnostics", default_value_t = false)]
    pub skip_diagnostics: bool,
}

impl Args {
    /// Run the relayer service.
    pub async fn run(self) -> eyre::Result<()> {
        let config_path = self.config.clone();
        try_spawn_with_args(self, &config_path).await?.server.stopped().await;

        Ok(())
    }

    /// Merges [`Args`] values into an existing [`RelayConfig`] instance.
    pub fn merge_relay_config(self, config: RelayConfig) -> RelayConfig {
        config
            .with_signers_mnemonic(self.signers_mnemonic)
            .with_public_node_endpoints(self.public_node_endpoints.clone())
            .with_fee_recipient(self.fee_recipient)
            .with_address(self.address)
            .with_port(self.port)
            .with_metrics_port(self.metrics_port)
            .with_max_connections(self.max_connections)
            .with_quote_ttl(self.quote_ttl)
            .with_rate_ttl(self.rate_ttl)
            .with_quote_constant_rate(self.constant_rate)
            .with_orchestrator(self.orchestrator)
            .with_delegation_proxy(self.delegation_proxy)
            .with_legacy_delegation_proxies(&self.legacy_delegation_proxies.unwrap_or_default())
            .with_simulator(self.simulator)
            .with_funder(self.funder)
            .with_escrow(self.escrow)
            .with_funder_key(self.funder_key)
            .with_service_api_key(self.service_api_key)
            .with_intent_gas_buffer(self.intent_gas_buffer)
            .with_tx_gas_buffer(self.tx_gas_buffer)
            .with_database_url(self.database_url)
            .with_max_pending_transactions(self.max_pending_transactions)
            .with_resend_api_key(self.resend_api_key)
            .with_porto_base_url(self.porto_base_url)
            .with_binance_keys(self.binance_api_key, self.binance_api_secret)
            .with_funder_owner_key(self.funder_owner_key)
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

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    #[test]
    fn test_debug_asserts() {
        super::Args::command().debug_assert();
    }
}
