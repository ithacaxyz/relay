use crate::{
    error::{QuoteError, RelayError},
    price::{PriceFetcher, oracle::PriceOracleMessage},
    types::{CoinKind, CoinPair, CoinRegistry},
};
use alloy::primitives::{Address, ChainId};
use alloy_chains::Chain;
use reqwest::get;
use std::{collections::HashMap, str::FromStr, sync::Arc, time::Duration};
use tokio::{sync::mpsc, time::interval};
use tracing::{error, trace, warn};

/// The time interval between fetching prices.
static PRICE_FETCH_INTERVAL: Duration = Duration::from_secs(60);

/// CoinGecko price fetcher;
#[derive(Debug)]
pub struct CoinGecko {
    /// URLs used to fetch prices.
    request_urls: Vec<(ChainId, String)>,
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
        let api_key = std::env::var("GECKO_API").unwrap_or_default();
        for (chain, tokens) in chains_with_tokens {
            let (platform, currency) = Self::identifiers(chain);
            let url = format!(
                "https://api.coingecko.com/api/v3/simple/token_price/{}?contract_addresses={}&vs_currencies={}&x_cg_demo_api_key={}",
                platform,
                tokens.iter().map(|t| t.to_string()).collect::<Vec<_>>().join(","),
                currency,
                &api_key
            );
            request_urls.push((chain, url))
        }

        let gecko = Self { coin_registry, request_urls, update_tx };

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

    /// Returns the platform and native currency identifiers.
    fn identifiers(chain: ChainId) -> (&'static str, &'static str) {
        let platform = if chain == Chain::base_goerli().id()
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
        };

        (platform, "eth")
    }

    /// Returns [`CoinKind`].
    fn parse_currency(currency: &str) -> Option<CoinKind> {
        if currency == "eth" {
            return Some(CoinKind::ETH);
        }
        None
    }

    /// Updates inner token prices.
    async fn update_prices(&self) -> Result<(), RelayError> {
        let timestamp =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

        for (chain, url) in &self.request_urls {
            // Fetch token prices
            let resp = async { get(url).await?.text().await }
                .await
                .inspect_err(|err| {
                    error!(
                        %err,
                        "Failed to fetch price from feed.",
                    );
                })
                .map_err(|_| QuoteError::UnavailablePriceFeed(*chain))?;

            trace!(response=?resp, "CoinGecko response.");

            if let Ok(data) = serde_json::from_str::<HashMap<String, HashMap<String, f64>>>(&resp) {
                let pairs = data.into_iter().filter_map(|(addr, inner)| {
                    // We only query one currency
                    let (currency, price) = inner.into_iter().next()?;

                    // todo validate price

                    Some((
                        CoinPair {
                            from: CoinKind::get_token(
                                &self.coin_registry,
                                *chain,
                                Address::from_str(&addr).ok()?,
                            )?,
                            to: Self::parse_currency(&currency)?,
                        },
                        price,
                    ))
                });

                let _ = self.update_tx.send(PriceOracleMessage::Update {
                    fetcher: PriceFetcher::CoinGecko,
                    prices: pairs.collect(),
                    timestamp,
                });

                continue;
            }
            error!(resp, "Not able to parse CoinGecko response.")
        }

        Ok(())
    }
}
