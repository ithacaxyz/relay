//! # Relay CLI
use crate::{config::RelayConfig, spawn::try_spawn_with_args};
use alloy::primitives::Address;
use clap::Parser;
use metrics_exporter_prometheus::PrometheusHandle;
use std::{net::IpAddr, path::PathBuf, time::Duration};
use url::Url;

/// The Ithaca relayer service sponsors transactions for EIP-7702 accounts.
#[derive(Debug, Parser)]
#[command(author, about = "Relay", long_about = None)]
pub struct Args {
    /// The configuration file.
    #[arg(long, value_name = "CONFIG", env = "RELAY_CONFIG", default_value = "relay.toml")]
    pub config: PathBuf,
    /// The address to serve the RPC on.
    #[arg(long = "http.addr", value_name = "ADDR")]
    pub address: Option<IpAddr>,
    /// The port to serve the RPC on.
    #[arg(long = "http.port", value_name = "PORT")]
    pub port: Option<u16>,
    /// The lifetime of a fee quote.
    #[arg(long, value_name = "SECONDS", value_parser = parse_duration_secs, default_value = "5")]
    pub quote_ttl: Option<Duration>,
    /// The RPC endpoint of a chain to send transactions to.
    ///
    /// Must be a valid HTTP or HTTPS URL pointing to an Ethereum JSON-RPC endpoint.
    #[arg(long = "endpoint", value_name = "RPC_ENDPOINT", required = true)]
    pub endpoints: Vec<Url>,
    /// A fee token the relay accepts.
    #[arg(long = "fee-token", value_name = "ADDRESS", required = true)]
    pub fee_tokens: Vec<Address>,
    /// The secret key to sign fee quotes with.
    #[arg(long, value_name = "SECRET_KEY", env = "RELAY_FEE_SK")]
    pub quote_secret_key: String,
    /// The secret key to sign transactions with.
    #[arg(long, value_name = "SECRET_KEY", env = "RELAY_SK")]
    pub secret_key: String,
}

impl Args {
    /// Run the relayer service.
    pub async fn run(self, metrics_recorder: Option<PrometheusHandle>) -> eyre::Result<()> {
        let config_path = self.config.clone();
        try_spawn_with_args(self, &config_path, metrics_recorder).await?.stopped().await;

        Ok(())
    }

    /// Merges [`Args`] values into an existing [`RelayConfig`] instance.
    pub fn merge_relay_config(self, mut config: RelayConfig) -> RelayConfig {
        config = config
            .with_quote_secret_key(self.quote_secret_key)
            .with_secret_key(self.secret_key)
            .with_endpoints(&self.endpoints)
            .with_fee_tokens(&self.fee_tokens);

        if let Some(address) = self.address {
            config = config.with_address(address);
        }

        if let Some(port) = self.port {
            config = config.with_port(port);
        }

        if let Some(quote_ttl) = self.quote_ttl {
            config = config.with_quote_ttl(quote_ttl);
        }

        config
    }
}

/// Parses a string representing seconds to a [`Duration`].
fn parse_duration_secs(arg: &str) -> Result<std::time::Duration, std::num::ParseIntError> {
    let seconds = arg.parse()?;
    Ok(std::time::Duration::from_secs(seconds))
}
