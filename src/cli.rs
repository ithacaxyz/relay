//! # Relay CLI
use crate::{
    config::RelayConfig,
    constants::{TX_GAS_BUFFER, USER_OP_GAS_BUFFER},
    spawn::try_spawn_with_args,
};
use alloy::primitives::Address;
use clap::Parser;
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
    /// `relay.toml`.
    #[arg(long, value_name = "CONFIG", env = "RELAY_CONFIG", default_value = "relay.toml")]
    pub config: PathBuf,
    /// The coin registry file. Maps chain ids and token addresses to coins (eg. ETH, USDC, USDT).
    ///
    /// If missing, a default one will be used and stored in the working directory under
    /// `registry.toml`.
    #[arg(long, value_name = "REGISTRY", env = "REGISTRY", default_value = "registry.toml")]
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
    /// The RPC endpoint of a chain to send transactions to.
    ///
    /// Must be a valid HTTP or HTTPS URL pointing to an Ethereum JSON-RPC endpoint.
    #[arg(long = "endpoint", value_name = "RPC_ENDPOINT", required = true)]
    pub endpoints: Vec<Url>,
    /// The lifetime of a fee quote.
    #[arg(long, value_name = "SECONDS", value_parser = parse_duration_secs, default_value = "5")]
    pub quote_ttl: Duration,
    /// Extra buffer added to UserOp gas estimates.
    #[arg(long, value_name = "USER_OP_GAS", default_value_t = USER_OP_GAS_BUFFER)]
    pub user_op_gas_buffer: u64,
    /// Extra buffer added to transaction gas estimates.
    #[arg(long, value_name = "TX_OP_GAS", default_value_t = TX_GAS_BUFFER)]
    pub tx_gas_buffer: u64,
    /// The secret key to sign fee quotes with.
    #[arg(long, value_name = "SECRET_KEY", env = "RELAY_FEE_SK")]
    pub quote_secret_key: String,
    /// A fee token the relay accepts.
    #[arg(long = "fee-token", value_name = "ADDRESS", required = true)]
    pub fee_tokens: Vec<Address>,
    /// The secret key to sign transactions with.
    #[arg(long, value_name = "SECRET_KEY", env = "RELAY_SK")]
    pub secret_key: String,
}

impl Args {
    /// Run the relayer service.
    pub async fn run(self) -> eyre::Result<()> {
        let config_path = self.config.clone();
        let registry_path = self.registry.clone();
        try_spawn_with_args(self, &config_path, &registry_path).await?.stopped().await;

        Ok(())
    }

    /// Merges [`Args`] values into an existing [`RelayConfig`] instance.
    pub fn merge_relay_config(self, config: RelayConfig) -> RelayConfig {
        config
            .with_quote_key(self.quote_secret_key)
            .with_transaction_key(self.secret_key)
            .with_endpoints(&self.endpoints)
            .with_fee_tokens(&self.fee_tokens)
            .with_address(self.address)
            .with_port(self.port)
            .with_metrics_port(self.metrics_port)
            .with_quote_ttl(self.quote_ttl)
            .with_user_op_gas_buffer(self.user_op_gas_buffer)
            .with_tx_gas_buffer(self.tx_gas_buffer)
    }
}

/// Parses a string representing seconds to a [`Duration`].
fn parse_duration_secs(arg: &str) -> Result<std::time::Duration, std::num::ParseIntError> {
    let seconds = arg.parse()?;
    Ok(std::time::Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::Args;
    use crate::spawn::try_spawn_with_args;
    use std::{
        env::temp_dir,
        net::{IpAddr, Ipv4Addr, TcpListener},
    };

    /// Finds an available port by binding to "127.0.0.1:0".
    fn get_available_port() -> std::io::Result<u16> {
        // Binding to port 0 tells the OS to assign an available port.
        let listener = TcpListener::bind("127.0.0.1:0")?;
        Ok(listener.local_addr()?.port())
    }

    #[tokio::test]
    async fn respawn_cli() -> eyre::Result<()> {
        let dir = temp_dir();
        let config = dir.join("relay.toml");
        let registry = dir.join("registry.toml");
        let key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

        for _ in 0..=1 {
            let _ = try_spawn_with_args(
                Args {
                    config: config.clone(),
                    registry: registry.clone(),
                    address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    port: get_available_port().unwrap(),
                    metrics_port: get_available_port().unwrap(),
                    endpoints: Default::default(),
                    quote_ttl: Default::default(),
                    quote_secret_key: key.to_string(),
                    fee_tokens: Default::default(),
                    secret_key: key.to_string(),
                    user_op_gas_buffer: Default::default(),
                    tx_gas_buffer: Default::default(),
                },
                config.clone(),
                registry.clone(),
            )
            .await?;
        }

        Ok(())
    }
}
