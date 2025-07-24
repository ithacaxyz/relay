use crate::{
    error::{QuoteError, RelayError},
    price::{PriceFetcher, oracle::PriceOracleMessage},
    types::{CoinKind, CoinPair, CoinRegistry},
};
use alloy::primitives::{Address, ChainId};
use alloy_chains::Chain;
use futures_util::{FutureExt, future::try_join_all};
use metrics::counter;
use reqwest::get;
use std::{
    collections::HashMap,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::mpsc, time::interval};
use tracing::{error, trace, warn};

/// The time interval between fetching prices.
static PRICE_FETCH_INTERVAL: Duration = Duration::from_secs(60);

/// CoinGecko price fetcher;
#[derive(Debug)]
pub struct CoinGecko {
    /// URLs used to fetch token prices.
    request_urls: Vec<(ChainId, String)>,
    /// URL used to fetch ETH price.
    eth_url: String,
    /// Price oracle sender used to update the price.
    update_tx: mpsc::UnboundedSender<PriceOracleMessage>,
    /// Coin registry.
    coin_registry: Arc<CoinRegistry>,
}

impl CoinGecko {
    /// Creates an instance of [`CoinGecko`] that sends a price feed to [`PriceOracle`] for all
    /// tokens from a spawned task every 10 seconds.
    pub fn launch(
        coin_registry: Arc<CoinRegistry>,
        pairs: &[CoinPair],
        update_tx: mpsc::UnboundedSender<PriceOracleMessage>,
    ) {
        if Self::api_key().is_empty() {
            warn!("GECKO_API environment variable not set, CoinGecko price fetcher will not run");
            return;
        }

        let request_urls = Self::build_request_urls(coin_registry.clone(), pairs);
        let eth_url = Self::build_url("simple/price", "ids=ethereum&vs_currencies=usd");

        let gecko = Self { coin_registry, request_urls, eth_url, update_tx };

        // Launch task to fetch prices on a fixed interval
        tokio::spawn(async move {
            let mut clock = interval(PRICE_FETCH_INTERVAL);

            loop {
                clock.tick().await;
                if let Err(err) = gecko.update_prices().await {
                    error!(?err);
                }
                clock.reset();
            }
        });
    }

    /// Builds request URLs for the given coin pairs.
    fn build_request_urls(
        coin_registry: Arc<CoinRegistry>,
        pairs: &[CoinPair],
    ) -> Vec<(ChainId, String)> {
        let mut chains_with_tokens: HashMap<ChainId, Vec<Address>> = HashMap::new();
        let eth_mainnet = Chain::mainnet().into();

        // Organize all pairs by platform and addresses
        for pair in pairs {
            // todo: only support eth native for now
            if pair.to.is_eth() {
                // Get all the chains that support this coin
                let chains = pair.from.get_chains(&coin_registry);

                if chains.is_empty() {
                    warn!(coin = ?pair.to, "Unsupported coin.")
                }

                // Give priority to ETH platform
                let chain = if chains.contains(&eth_mainnet) { eth_mainnet } else { chains[0] };

                // Organize tokens by chain with no repeated tokens across chains.
                if let Some(token_address) = pair.from.get_token_address(&coin_registry, chain) {
                    chains_with_tokens.entry(chain).or_default().push(token_address);
                } else {
                    warn!(token = ?pair.from, ?chain, "Did not find token address.")
                }
            } else {
                unreachable!("For now, we only support ETH.")
            }
        }

        // Transform chains_with_tokens into a list of (Chain, URL).
        let mut request_urls = vec![];
        for (chain, tokens) in chains_with_tokens {
            let params = format!(
                "contract_addresses={}&vs_currencies=eth,usd",
                tokens.iter().map(|t| t.to_string()).collect::<Vec<_>>().join(",")
            );
            let url = Self::build_url(
                &format!("simple/token_price/{}", Self::platform_identifier(chain)),
                &params,
            );
            request_urls.push((chain, url))
        }

        request_urls
    }

    /// Returns the platform identifier for the given chain.
    fn platform_identifier(chain: ChainId) -> &'static str {
        if chain == Chain::base_goerli().id()
            || chain == Chain::base_sepolia().id()
            || chain == Chain::base_mainnet().id()
        {
            "base"
        } else if chain == Chain::optimism_goerli().id()
            || chain == Chain::optimism_sepolia().id()
            || chain == Chain::optimism_mainnet().id()
        {
            "optimistic-ethereum"
        } else {
            "ethereum"
        }
    }

    /// Returns the API key for CoinGecko.
    fn api_key() -> String {
        std::env::var("GECKO_API").unwrap_or_default()
    }

    /// Builds a CoinGecko API URL with the API key.
    fn build_url(path: &str, params: &str) -> String {
        format!(
            "https://pro-api.coingecko.com/api/v3/{}?{}&x_cg_pro_api_key={}",
            path,
            params,
            Self::api_key()
        )
    }

    /// Fetches data from a URL and returns the response as text.
    async fn fetch_url(url: &str, chain: ChainId) -> Result<String, RelayError> {
        async { get(url).await?.text().await }
            .await
            .inspect_err(|err| {
                error!(
                    %err,
                    %url,
                    "Failed to fetch price from feed.",
                );
            })
            .map_err(|_| QuoteError::UnavailablePriceFeed(chain).into())
    }

    /// Fetches ETH USD price using the simple price API.
    async fn update_eth_price(&self, timestamp: Instant) -> Result<(), RelayError> {
        let resp = Self::fetch_url(&self.eth_url, Chain::mainnet().into()).await?;

        if let Ok(data) = serde_json::from_str::<HashMap<String, HashMap<String, f64>>>(&resp) {
            if let Some(eth_prices) = data.get("ethereum")
                && let Some(&usd_price) = eth_prices.get("usd")
            {
                trace!(eth_usd_price = usd_price, "Fetched ETH USD price");
                let _ = self.update_tx.send(PriceOracleMessage::UpdateUsd {
                    fetcher: PriceFetcher::CoinGecko,
                    prices: vec![(CoinKind::ETH, usd_price)],
                    timestamp,
                });
            }
        } else {
            error!(resp, "Not able to parse ETH price response.")
        }

        Ok(())
    }

    /// Fetches token prices for a specific chain.
    async fn update_token_prices(
        &self,
        chain: ChainId,
        url: &str,
        timestamp: Instant,
    ) -> Result<(), RelayError> {
        let resp = Self::fetch_url(url, chain).await?;
        trace!(response=?resp, "CoinGecko response.");

        if let Ok(data) = serde_json::from_str::<HashMap<String, HashMap<String, f64>>>(&resp) {
            let mut eth_pairs = Vec::new();
            let mut usd_prices = Vec::new();

            for (addr, currencies) in data {
                let token_address = match Address::from_str(&addr) {
                    Ok(addr) => addr,
                    Err(_) => continue,
                };

                let from_coin = match CoinKind::get_token(&self.coin_registry, chain, token_address)
                {
                    Some(coin) => coin,
                    None => continue,
                };

                // Process all currency prices for this token
                for (currency, price) in currencies {
                    match currency.as_str() {
                        "eth" => {
                            // todo validate price
                            eth_pairs
                                .push((CoinPair { from: from_coin, to: CoinKind::ETH }, price));
                        }
                        "usd" => {
                            trace!(
                                token = ?from_coin,
                                usd_price = price,
                                "Fetched USD price for token"
                            );
                            // todo validate price
                            usd_prices.push((from_coin, price));
                        }
                        _ => {
                            warn!(currency = ?currency, "Unknown currency in CoinGecko response.");
                        }
                    }
                }
            }

            counter!("coingecko.last_update")
                .absolute(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());

            if !eth_pairs.is_empty() {
                let _ = self.update_tx.send(PriceOracleMessage::Update {
                    fetcher: PriceFetcher::CoinGecko,
                    prices: eth_pairs,
                    timestamp,
                });
            }

            if !usd_prices.is_empty() {
                let _ = self.update_tx.send(PriceOracleMessage::UpdateUsd {
                    fetcher: PriceFetcher::CoinGecko,
                    prices: usd_prices,
                    timestamp,
                });
            }
        } else {
            error!(resp, "Not able to parse CoinGecko response.")
        }

        Ok(())
    }

    /// Updates inner token prices.
    async fn update_prices(&self) -> Result<(), RelayError> {
        let timestamp = Instant::now();

        try_join_all(
            std::iter::once(self.update_eth_price(timestamp).boxed()).chain(
                self.request_urls
                    .iter()
                    .map(|(chain, url)| self.update_token_prices(*chain, url, timestamp).boxed()),
            ),
        )
        .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn test_coingecko_usd_prices() {
        let _ = std::env::var("GECKO_API").unwrap();

        let registry = Arc::new(CoinRegistry::default());
        let (update_tx, mut update_rx) = mpsc::unbounded_channel();
        let pairs = CoinPair::ethereum_pairs(&[CoinKind::USDT, CoinKind::USDC]);

        let gecko = CoinGecko {
            request_urls: CoinGecko::build_request_urls(registry.clone(), &pairs),
            coin_registry: registry,
            eth_url: CoinGecko::build_url("simple/price", "ids=ethereum&vs_currencies=usd"),
            update_tx,
        };

        gecko.update_prices().await.expect("Failed to fetch prices");

        let mut usd_prices = HashMap::new();
        let mut eth_prices = HashMap::new();

        while let Ok(msg) = update_rx.try_recv() {
            match msg {
                PriceOracleMessage::UpdateUsd { prices, .. } => {
                    for (coin, price) in prices {
                        usd_prices.insert(coin, price);
                    }
                }
                PriceOracleMessage::Update { prices, .. } => {
                    for (pair, price) in prices {
                        eth_prices.insert(pair.from, price);
                    }
                }
                _ => {}
            }
        }

        // Verify we got USD prices for all coins
        for coin in [CoinKind::ETH, CoinKind::USDT, CoinKind::USDC] {
            let price = usd_prices.get(&coin).copied().unwrap_or_else(|| {
                panic!("Missing USD price for {coin:?}. Got USD prices: {usd_prices:?}")
            });
            assert!(price > 0.0, "Invalid USD price for {coin:?}: {price}");
        }

        // Verify we got ETH prices for tokens
        for coin in [CoinKind::USDT, CoinKind::USDC] {
            let price = eth_prices.get(&coin).copied().unwrap_or_else(|| {
                panic!("Missing ETH price for {coin:?}. Got ETH prices: {eth_prices:?}")
            });
            assert!(price > 0.0, "Invalid ETH price for {coin:?}: {price}");
        }
    }
}
