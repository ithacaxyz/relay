//! Relay configuration.
use crate::types::CoinKind;
use alloy::primitives::{Address, ChainId};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    path::Path,
    sync::Arc,
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
    /// Secrets.
    #[serde(skip_serializing, default)]
    pub secrets: SecretsConfig,
    /// Global map from ([ChainId], Option<[Address]>) to [CoinKind].
    pub coin_registry: Arc<HashMap<(ChainId, Option<Address>), CoinKind>>,
}

/// Server configuration.
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    /// The address to serve the RPC on.
    pub address: IpAddr,
    /// The port to serve the RPC on.
    pub port: u16,
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
#[derive(Debug, Serialize, Deserialize)]
pub struct QuoteConfig {
    /// The lifetime of a fee quote.
    #[serde(with = "crate::serde::duration")]
    pub ttl: Duration,
    /// Sets a constant rate for the price oracle. Used for testing.
    pub constant_rate: Option<f64>,
}

/// Secrets (kept out of serialized output).
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SecretsConfig {
    /// The secret key to sign transactions with.
    pub transaction_key: String,
    /// The secret key to sign fee quotes with.
    pub quote_key: String,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig { address: IpAddr::V4(Ipv4Addr::LOCALHOST), port: 9119 },
            chain: ChainConfig { endpoints: vec![], fee_tokens: vec![] },
            quote: QuoteConfig { ttl: Duration::from_secs(5), constant_rate: None },
            secrets: SecretsConfig::default(),
            coin_registry: Default::default(),
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

    /// Sets the lifetime duration for fee quotes.
    pub fn with_quote_ttl(mut self, quote_ttl: Duration) -> Self {
        self.quote.ttl = quote_ttl;
        self
    }

    /// Sets a constant rate for the price oracle. Used for testing.
    pub fn with_quote_constant_rate(mut self, constant_rate: f64) -> Self {
        self.quote.constant_rate = Some(constant_rate);
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
        self.secrets.transaction_key = secret_key;
        self
    }

    /// Extend the coin registry with additional entries.
    pub fn extend_coin_registry(
        mut self,
        registry: HashMap<(ChainId, Option<Address>), CoinKind>,
    ) -> Self {
        let mut new_registry = (*self.coin_registry).clone();
        new_registry.extend(registry);
        self.coin_registry = Arc::new(new_registry);
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
