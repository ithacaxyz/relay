use crate::error::{QuoteError, RelayError};
use alloy::primitives::{Address, ChainId};
use alloy_chains::Chain;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{collections::HashMap, str::FromStr};
use tracing::error;

/// Response from the /prices/current endpoint
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PriceResponse {
    /// Map of coin identifier to price data
    pub coins: HashMap<String, CoinData>,
}

/// Price information for a specific coin
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CoinData {
    /// Current price in USD
    pub price: f64,
    /// Token symbol (e.g., "ETH", "SOL")
    #[serde(default)]
    pub symbol: String,
    /// Timestamp of the price data (Unix timestamp)
    #[serde(default)]
    pub timestamp: u64,
    /// Confidence score (0-1) indicating reliability of price data
    #[serde(default)]
    pub confidence: f64,
    /// Decimals for the token
    #[serde(default)]
    pub decimals: Option<u8>,
}

/// DeFiLlama price fetcher client.
#[derive(Debug, Clone)]
pub struct DeFiLlamaClient {
    /// HTTP client for making requests.
    client: reqwest::Client,
    /// Base URL for the API.
    base_url: String,
}

impl Default for DeFiLlamaClient {
    fn default() -> Self {
        Self::new()
    }
}

impl DeFiLlamaClient {
    /// Creates a new DeFiLlama client.
    pub fn new() -> Self {
        Self { client: reqwest::Client::new(), base_url: "https://coins.llama.fi".to_string() }
    }

    /// Configures the base url which might include the API key.
    pub fn with_base_url(mut self, base_url: String) -> Self {
        self.base_url = base_url;
        self
    }

    /// Fetches current prices for the given coin identifiers.
    ///
    /// Coin identifiers should be in the format "chain:address", e.g.:
    /// - "ethereum:0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" for USDC on Ethereum
    /// - "ethereum:0x0000000000000000000000000000000000000000" for ETH
    pub async fn get_prices(&self, coins: &[String]) -> Result<PriceResponse, RelayError> {
        let url = format!("{}/prices/current/{}", self.base_url, coins.join(","));
        self.fetch_url(&url).await
    }

    /// Fetches USD price for a single token.
    pub async fn get_token_price(
        &self,
        chain: ChainId,
        token_address: Address,
    ) -> Result<Option<f64>, RelayError> {
        let chain_id = Self::chain_identifier(chain);
        let coin_id = format!("{chain_id}:{token_address}");

        let response = self.get_prices(std::slice::from_ref(&coin_id)).await?;

        Ok(response.coins.get(&coin_id).map(|data| data.price))
    }

    /// Fetches USD prices for multiple tokens on a chain.
    pub async fn get_token_prices(
        &self,
        chain: ChainId,
        token_addresses: &[Address],
    ) -> Result<HashMap<Address, f64>, RelayError> {
        let chain_id = Self::chain_identifier(chain);
        let coin_ids: Vec<String> =
            token_addresses.iter().map(|addr| format!("{chain_id}:{addr}")).collect();

        let response = self.get_prices(&coin_ids).await?;

        let mut prices = HashMap::with_capacity(response.coins.len());
        for (coin_id, data) in response.coins {
            if let Some((_, addr_str)) = coin_id.split_once(':')
                && let Ok(addr) = Address::from_str(addr_str)
            {
                prices.insert(addr, data.price);
            }
        }

        Ok(prices)
    }

    /// Fetches ETH USD price.
    pub async fn get_eth_price(&self) -> Result<Option<f64>, RelayError> {
        let eth_id = "ethereum:0x0000000000000000000000000000000000000000";
        let response = self.get_prices(&[eth_id.to_string()]).await?;

        Ok(response.coins.get(eth_id).map(|data| data.price))
    }

    /// Returns the chain identifier for the given chain.
    fn chain_identifier(chain: ChainId) -> &'static str {
        if chain == Chain::base_goerli().id()
            || chain == Chain::base_sepolia().id()
            || chain == Chain::base_mainnet().id()
        {
            "base"
        } else if chain == Chain::optimism_goerli().id()
            || chain == Chain::optimism_sepolia().id()
            || chain == Chain::optimism_mainnet().id()
        {
            "optimism"
        } else if chain == Chain::arbitrum_mainnet().id() || chain == Chain::arbitrum_sepolia().id()
        {
            "arbitrum"
        } else {
            "ethereum"
        }
    }

    /// Fetches data from a URL and deserializes the JSON response.
    async fn fetch_url<T: DeserializeOwned>(&self, url: &str) -> Result<T, RelayError> {
        self.client
            .get(url)
            .send()
            .await?
            .json::<T>()
            .await
            .inspect_err(|err| {
                error!(%err, %url, "Failed to fetch from DeFiLlama");
            })
            .map_err(|_| QuoteError::UnavailablePriceFeed(Chain::mainnet().into()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;
    use alloy_chains::Chain;

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn test_defillama_eth_price() {
        let client = DeFiLlamaClient::new();

        let eth_price = client.get_eth_price().await.expect("Failed to fetch ETH price");

        assert!(eth_price.is_some());
        let price = eth_price.unwrap();
        assert!(price > 0.0, "ETH price should be positive");
        assert!(price < 1_000_000.0, "ETH price sanity check");
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn test_defillama_token_prices() {
        let client = DeFiLlamaClient::new();

        // USDC address on Ethereum
        let usdc_address = address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
        // USDT address on Ethereum
        let usdt_address = address!("dAC17F958D2ee523a2206206994597C13D831ec7");

        let prices = client
            .get_token_prices(Chain::mainnet().into(), &[usdc_address, usdt_address])
            .await
            .expect("Failed to fetch token prices");

        assert_eq!(prices.len(), 2);

        let usdc_price = prices.get(&usdc_address).expect("USDC price not found");
        assert!(*usdc_price > 0.9 && *usdc_price < 1.1, "USDC price should be around $1");

        let usdt_price = prices.get(&usdt_address).expect("USDT price not found");
        assert!(*usdt_price > 0.9 && *usdt_price < 1.1, "USDT price should be around $1");
    }
}
