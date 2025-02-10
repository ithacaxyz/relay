use crate::{
    error::PriceOracleError,
    price::{oracle::PriceOracleMessage, PriceFetcher},
    types::{CoinKind, CoinPair},
};
use alloy::primitives::Address;
use alloy_chains::Chain;
use reqwest::get;
use std::{collections::HashMap, str::FromStr, time::Duration};
use tokio::{sync::mpsc, time::interval};
use tracing::{error, trace, warn};

/// CoinGecko price fetcher;
#[derive(Debug)]
pub struct CoinGecko {
    /// URLs used to fetch prices.
    request_urls: Vec<(Chain, String)>,
    /// Price oracle sender used to update the price.
    update_tx: mpsc::UnboundedSender<PriceOracleMessage>,
}

impl CoinGecko {
    /// Creates an instance of [`CoinGecko`] that sends a price feed to [`PriceOracle`] for all
    /// tokens from a spawned task every 10 seconds.
    pub fn launch(pairs: &[CoinPair], update_tx: mpsc::UnboundedSender<PriceOracleMessage>) {
        let mut chains_with_tokens: HashMap<Chain, Vec<Address>> = HashMap::new();
        let eth_mainnet = Chain::mainnet();

        // Organize all pairs by platform and addresses
        for pair in pairs {
            // todo: only support eth native for now
            if pair.to.is_eth() {
                // Get all the chains that support this coin
                let chains = pair.from.get_chains();

                if chains.is_empty() {
                    warn!(coin = ?pair.to, "Unsupported coin.")
                }

                // Give priority to ETH platform
                let chain = if chains.contains(&eth_mainnet) { eth_mainnet } else { chains[0] };

                // Organize tokens by chain with no repeated tokens across chains.
                if let Some(token_address) = pair.from.get_token_address(chain) {
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

        let gecko = Self { request_urls, update_tx };

        // Launch task to fetch prices every 10 seconds
        tokio::spawn(async move {
            let mut clock = interval(Duration::from_secs(10));

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
    fn identifiers(chain: Chain) -> (&'static str, &'static str) {
        let platform = if chain == Chain::base_goerli()
            || chain == Chain::base_sepolia()
            || chain == Chain::base_mainnet()
        {
            "base"
        } else if chain == Chain::optimism_goerli()
            || chain == Chain::optimism_sepolia()
            || chain == Chain::optimism_mainnet()
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
    async fn update_prices(&self) -> Result<(), PriceOracleError> {
        let timestamp =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

        for (chain, url) in &self.request_urls {
            // Fetch token prices
            let resp = get(url)
                .await
                .map_err(|err| PriceOracleError::InternalError(err.into()))?
                .text()
                .await
                .map_err(|err| PriceOracleError::InternalError(err.into()))?;

            trace!(response=?resp, "CoinGecko response.");

            let data: HashMap<String, HashMap<String, f64>> = serde_json::from_str(&resp).unwrap();
            let pairs = data.into_iter().filter_map(|(addr, inner)| {
                // We only query one currency
                let (currency, price) = inner.into_iter().next()?;

                // todo validate price

                Some((
                    CoinPair {
                        from: CoinKind::get_token(*chain, Address::from_str(&addr).ok()?)?,
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
        }

        Ok(())
    }
}
