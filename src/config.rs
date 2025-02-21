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

/// Configurations of the relay
#[derive(Debug, Serialize, Deserialize)]
pub struct RelayConfig {
    /// The address to serve the RPC on.
    pub address: IpAddr,
    /// The port to serve the RPC on.
    pub port: u16,
    /// The RPC endpoint of a chain to send transactions to.
    pub endpoints: Vec<Url>,
    /// A fee token the relay accepts.
    pub fee_tokens: Vec<Address>,
    /// The lifetime of a fee quote.
    pub quote_ttl: Duration,
    /// The secret key to sign transactions with.
    #[serde(skip_serializing)]
    pub secret_key: String,
    /// The secret key to sign fee quotes with.
    #[serde(skip_serializing)]
    pub quote_secret_key: String,
    /// Sets a constant rate for the price oracle. Used for testing.
    pub constant_rate: Option<f64>,
    /// Global map from ([ChainId], Option<[Address]>) to [CoinKind].
    pub coin_registry: Arc<HashMap<(ChainId, Option<Address>), CoinKind>>,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 9119,
            endpoints: Vec::new(),
            quote_ttl: Duration::from_secs(5),
            quote_secret_key: String::new(),
            fee_tokens: Vec::new(),
            secret_key: String::new(),
            constant_rate: None,
            coin_registry: Arc::new(HashMap::new()),
        }
    }
}

impl RelayConfig {
    /// Sets the IP address to serve the RPC on.
    pub fn with_address(mut self, address: IpAddr) -> Self {
        self.address = address;
        self
    }

    /// Sets the port to serve the RPC on.
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Sets the list of RPC endpoints (as URLs) for the chain transactions.
    pub fn with_endpoints(mut self, endpoints: Vec<Url>) -> Self {
        self.endpoints = endpoints;
        self
    }

    /// Sets the lifetime duration for fee quotes.
    pub fn with_quote_ttl(mut self, quote_ttl: Duration) -> Self {
        self.quote_ttl = quote_ttl;
        self
    }

    /// Sets the secret key used to sign fee quotes.
    pub fn with_quote_secret_key<S: Into<String>>(mut self, key: S) -> Self {
        self.quote_secret_key = key.into();
        self
    }

    /// Sets the list of fee tokens that the relay accepts.
    pub fn with_fee_tokens(mut self, fee_tokens: Vec<Address>) -> Self {
        self.fee_tokens = fee_tokens;
        self
    }

    /// Sets the secret key used to sign transactions.
    pub fn with_secret_key<S: Into<String>>(mut self, key: S) -> Self {
        self.secret_key = key.into();
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

    /// Sets a constant rate for the price oracle. Used for testing.
    pub fn with_constant_rate(mut self, constant_rate: f64) -> Self {
        self.constant_rate = Some(constant_rate);
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
