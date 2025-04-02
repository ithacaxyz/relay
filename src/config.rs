//! Relay configuration.
use crate::constants::{TX_GAS_BUFFER, USER_OP_GAS_BUFFER};
use alloy::primitives::Address;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr},
    path::Path,
    time::Duration,
};

/// Relay configuration.
#[derive(Debug, Serialize, Deserialize)]
pub struct RelayConfig {
    /// Server configuration.
    pub server: ServerConfig,
    /// Chain configuration.
    pub chain: ChainConfig,
    /// Quote configuration.
    pub quote: QuoteConfig,
    /// Entrypoint address.
    pub entrypoint: Address,
    /// Secrets.
    #[serde(skip_serializing, default)]
    pub secrets: SecretsConfig,
    /// Database URL.
    pub database_url: Option<String>,
}

/// Server configuration.
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    /// The address to serve the RPC on.
    pub address: IpAddr,
    /// The port to serve the RPC on.
    pub port: u16,
    /// The port to serve the metrics on.
    pub metrics_port: u16,
}

/// Chain configuration.
#[derive(Debug, Serialize, Deserialize)]
pub struct ChainConfig {
    /// The RPC endpoint of a chain to send transactions to.
    pub endpoints: Vec<Url>,
    /// A fee token the relay accepts.
    pub fee_tokens: Vec<Address>,
}

/// Quote configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuoteConfig {
    /// Sets a constant rate for the price oracle. Used for testing.
    pub constant_rate: Option<f64>,
    /// Gas estimate configuration.
    gas: GasConfig,
    /// The lifetime of a fee quote.
    #[serde(with = "crate::serde::duration")]
    pub ttl: Duration,
    /// The lifetime of a price rate.
    #[serde(with = "crate::serde::duration")]
    pub rate_ttl: Duration,
}

/// Gas estimate configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GasConfig {
    /// Extra buffer added to UserOp gas estimates.
    pub user_op_buffer: u64,
    /// Extra buffer added to transaction gas estimates.
    pub tx_buffer: u64,
}

impl QuoteConfig {
    /// Returns the configured extra buffer added to userOp gas estimates.
    pub fn user_op_buffer(&self) -> u64 {
        self.gas.user_op_buffer
    }

    /// Returns the configured extra buffer added to transaction gas estimates.
    pub fn tx_buffer(&self) -> u64 {
        self.gas.tx_buffer
    }
}

/// Secrets (kept out of serialized output).
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SecretsConfig {
    /// The secret key to sign transactions with.
    pub transaction_keys: Vec<String>,
    /// The secret key to sign fee quotes with.
    pub quote_key: String,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 9119,
                metrics_port: 9000,
            },
            chain: ChainConfig { endpoints: vec![], fee_tokens: vec![] },
            quote: QuoteConfig {
                constant_rate: None,
                gas: GasConfig { user_op_buffer: USER_OP_GAS_BUFFER, tx_buffer: TX_GAS_BUFFER },
                ttl: Duration::from_secs(5),
                rate_ttl: Duration::from_secs(300),
            },
            entrypoint: Address::ZERO,
            secrets: SecretsConfig::default(),
            database_url: None,
        }
    }
}

impl RelayConfig {
    /// Sets the IP address to serve the RPC on.
    pub fn with_address(mut self, address: IpAddr) -> Self {
        self.server.address = address;
        self
    }

    /// Sets the port to serve the RPC on.
    pub fn with_port(mut self, port: u16) -> Self {
        self.server.port = port;
        self
    }

    /// Sets the port to serve the metrics on.
    pub fn with_metrics_port(mut self, port: u16) -> Self {
        self.server.metrics_port = port;
        self
    }

    /// Sets the lifetime duration for fee quotes.
    pub fn with_quote_ttl(mut self, quote_ttl: Duration) -> Self {
        self.quote.ttl = quote_ttl;
        self
    }

    /// Sets the lifetime duration for token price rates.
    pub fn with_rate_ttl(mut self, rate_ttl: Duration) -> Self {
        self.quote.rate_ttl = rate_ttl;
        self
    }

    /// Sets a constant rate for the price oracle. Used for testing.
    pub fn with_quote_constant_rate(mut self, constant_rate: f64) -> Self {
        self.quote.constant_rate = Some(constant_rate);
        self
    }

    /// Sets the buffer added to UserOp gas estimates.
    pub fn with_user_op_gas_buffer(mut self, buffer: u64) -> Self {
        self.quote.gas.user_op_buffer = buffer;
        self
    }

    /// Sets the buffer added to tx gas estimates.
    pub fn with_tx_gas_buffer(mut self, buffer: u64) -> Self {
        self.quote.gas.tx_buffer = buffer;
        self
    }

    /// Extends the list of fee tokens that the relay accepts.
    pub fn with_fee_tokens(mut self, fee_tokens: &[Address]) -> Self {
        self.chain.fee_tokens.extend_from_slice(fee_tokens);
        self
    }

    /// Extends the list of RPC endpoints (as URLs) for the chain transactions.
    pub fn with_endpoints(mut self, endpoints: &[Url]) -> Self {
        self.chain.endpoints.extend_from_slice(endpoints);
        self
    }

    /// Sets the secret key used to sign fee quotes.
    pub fn with_quote_key(mut self, quote_secret_key: String) -> Self {
        self.secrets.quote_key = quote_secret_key;
        self
    }

    /// Sets the secret key used to sign transactions.
    pub fn with_transaction_key(mut self, secret_key: String) -> Self {
        self.secrets.transaction_keys.push(secret_key);
        self
    }

    /// Sets the secret key used to sign transactions.
    pub fn with_transaction_keys(mut self, secret_keys: &[String]) -> Self {
        self.secrets.transaction_keys.extend_from_slice(secret_keys);
        self
    }

    /// Sets the entrypoint address.
    pub fn with_entrypoint(mut self, entrypoint: Address) -> Self {
        self.entrypoint = entrypoint;
        self
    }

    /// Sets the database URL.
    pub fn with_database_url(mut self, database_url: Option<String>) -> Self {
        self.database_url = database_url;
        self
    }

    /// Load from a TOML file.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> eyre::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config = toml::from_str(&content)?;
        Ok(config)
    }

    /// Save to a TOML file.
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> eyre::Result<()> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}
