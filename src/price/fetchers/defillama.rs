use crate::{
    config::RelayConfig,
    error::{QuoteError, RelayError},
    price::oracle::PriceOracleMessage,
    types::AssetUid,
};
use alloy::primitives::{Address, ChainId};
use alloy_chains::Chain;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::HashMap,
    str::FromStr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::mpsc, time::interval};
use tracing::{error, trace};

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
            .map_err(|_| QuoteError::UnavailablePriceFeed.into())
    }
}

/// Fetcher that periodically pulls USD prices from DeFiLlama and updates the price oracle.
#[derive(Debug, Clone)]
pub struct DeFiLlama {
    /// The HTTP client.
    client: DeFiLlamaClient,
    /// Price oracle sender used to update the price.
    update_tx: mpsc::UnboundedSender<PriceOracleMessage>,
    /// Map of `chain:address` coin identifiers to asset UIDs to update.
    assets: HashMap<String, Vec<AssetUid>>,
}

impl DeFiLlama {
    /// The time interval between fetching prices.
    const PRICE_FETCH_INTERVAL: Duration = Duration::from_secs(60);

    /// Creates a new DeFiLlama fetcher.
    pub fn new(
        client: DeFiLlamaClient,
        update_tx: mpsc::UnboundedSender<PriceOracleMessage>,
        assets: HashMap<String, Vec<AssetUid>>,
    ) -> Self {
        Self { client, update_tx, assets }
    }

    /// Launches the DeFiLlama fetcher task from config.
    pub fn launch(update_tx: mpsc::UnboundedSender<PriceOracleMessage>, config: &RelayConfig) {
        // Build mapping: coin_id ("chain:address") -> [AssetUid]
        let mut mapping: HashMap<String, Vec<AssetUid>> = HashMap::new();
        for (chain, chain_cfg) in &config.chains {
            let chain_ident = DeFiLlamaClient::chain_identifier(chain.id());
            for (uid, desc) in chain_cfg.assets.iter() {
                let coin_id = format!("{}:{}", chain_ident, desc.address);
                mapping.entry(coin_id).or_default().push(uid.clone());
            }
        }

        let fetcher = Self::new(DeFiLlamaClient::new(), update_tx, mapping);

        tokio::spawn(async move {
            let mut clock = interval(Self::PRICE_FETCH_INTERVAL);
            loop {
                clock.tick().await;
                if let Err(err) = fetcher.update_prices().await {
                    error!(?err, "defillama: update failed");
                }
                clock.reset();
            }
        });
    }

    /// Fetch prices and push to oracle.
    async fn update_prices(&self) -> Result<(), RelayError> {
        if self.assets.is_empty() {
            return Ok(());
        }

        let timestamp = Instant::now();
        let ids: Vec<String> = self.assets.keys().cloned().collect();
        let resp = self.client.get_prices(&ids).await?;

        trace!(count = resp.coins.len(), "defillama: received prices");

        // Map response to AssetUid prices using our mapping.
        let mut prices = Vec::new();
        for (coin_id, data) in resp.coins {
            if let Some(uids) = self.assets.get(&coin_id) {
                for uid in uids {
                    prices.push((uid.clone(), data.price));
                }
            }
        }

        metrics::counter!("defillama.last_update")
            .absolute(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());

        let _ = self.update_tx.send(PriceOracleMessage::UpdateUsd {
            fetcher: crate::price::fetchers::PriceFetcher::DeFiLlama,
            prices,
            timestamp,
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::info;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_defillama_token_prices() {
        let client = DeFiLlamaClient::new();

        let assets = HashMap::from_iter([
            ("ethereum".into(), vec![AssetUid::new("eth".into())]),
            ("usd-coin".into(), vec![AssetUid::new("usdc".into())]),
        ]);
        let (update_tx, mut update_rx) = mpsc::unbounded_channel();
        let defillama = DeFiLlama::new(client, update_tx, assets.clone());

        defillama.update_prices().await.expect("Failed to fetch token prices");

        let mut usd_prices = HashMap::new();

        info!("Processing messages...");
        while let Ok(msg) = update_rx.try_recv() {
            if let PriceOracleMessage::UpdateUsd { prices, .. } = msg {
                info!("Received USD prices update with {} prices", prices.len());
                for (coin, price) in prices {
                    info!("{}: {}", coin, price);
                    usd_prices.insert(coin, price);
                }
            }
        }
    }
}
