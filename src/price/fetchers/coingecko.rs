use crate::{
    config::RelayConfig,
    error::{QuoteError, RelayError},
    price::{PriceFetcher, oracle::PriceOracleMessage},
    types::AssetUid,
};
use itertools::Itertools;
use metrics::counter;
use std::{
    collections::HashMap,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::mpsc, time::interval};
use tracing::{error, trace, warn};

/// The time interval between fetching prices.
static PRICE_FETCH_INTERVAL: Duration = Duration::from_secs(60);

/// CoinGecko price fetcher;
#[derive(Debug)]
pub struct CoinGecko {
    /// The request URL.
    url: String,
    /// Price oracle sender used to update the price.
    update_tx: mpsc::UnboundedSender<PriceOracleMessage>,
    /// A map of coin IDs to asset UIDs.
    assets: HashMap<String, AssetUid>,
}

impl CoinGecko {
    /// Creates a new [`CoinGecko`] instance.
    pub fn new(
        api_key: String,
        update_tx: mpsc::UnboundedSender<PriceOracleMessage>,
        assets: HashMap<String, AssetUid>,
    ) -> Self {
        let ids = assets.keys().join(",");

        let url = format!(
            "https://pro-api.coingecko.com/api/v3/simple/price?ids={ids}&vs_currencies=usd&x_cg_pro_api_key={api_key}",
        );

        Self { url, update_tx, assets }
    }

    /// Creates an instance of [`CoinGecko`] that sends a price feed to [`PriceOracle`] for all
    /// tokens from a spawned task every 10 seconds.
    pub fn launch(update_tx: mpsc::UnboundedSender<PriceOracleMessage>, config: &RelayConfig) {
        if Self::api_key().is_empty() {
            warn!("GECKO_API environment variable not set, CoinGecko price fetcher will not run");
            return;
        }
        let assets = config
            .chains
            .iter()
            .flat_map(|(_, chain)| chain.assets.iter())
            .map(|(uid, _)| {
                let remapped = config
                    .pricefeed
                    .coingecko
                    .remapping
                    .get(uid)
                    .cloned()
                    .unwrap_or(uid.as_str().into());
                (remapped, uid.clone())
            })
            .collect();

        let gecko = Self::new(Self::api_key(), update_tx, assets);

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

    /// Returns the API key for CoinGecko.
    fn api_key() -> String {
        std::env::var("GECKO_API").unwrap_or_default()
    }

    /// Updates inner token prices.
    async fn update_prices(&self) -> Result<(), RelayError> {
        let timestamp = Instant::now();

        let resp = reqwest::get(&self.url)
            .await?
            .text()
            .await
            .inspect_err(|err| {
                error!(
                    %err,
                    %self.url,
                    "Failed to fetch price from feed.",
                );
            })
            .map_err(|_| QuoteError::UnavailablePriceFeed)?;

        trace!(response=?resp, "CoinGecko response.");

        let Ok(data) = serde_json::from_str::<HashMap<String, HashMap<String, f64>>>(&resp) else {
            error!(resp, "Not able to parse CoinGecko response.");
            return Ok(());
        };

        let prices = self
            .assets
            .iter()
            .filter_map(|(coin_id, uid)| {
                let price = *data.get(coin_id).and_then(|prices| prices.get("usd"))?;
                trace!(
                    token = ?uid,
                    usd_price = price,
                    "Fetched USD price for token"
                );
                Some((uid.clone(), price))
            })
            .collect();

        counter!("coingecko.last_update")
            .absolute(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());

        let _ = self.update_tx.send(PriceOracleMessage::UpdateUsd {
            fetcher: PriceFetcher::CoinGecko,
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
    #[ignore]
    async fn test_coingecko_usd_prices() {
        let api_key = std::env::var("GECKO_API").unwrap();
        info!("Using API key: {}", if api_key.is_empty() { "EMPTY" } else { "SET" });

        let assets = HashMap::from_iter([
            ("ethereum".into(), AssetUid::new("eth".into())),
            ("usd-coin".into(), AssetUid::new("usdc".into())),
        ]);
        let (update_tx, mut update_rx) = mpsc::unbounded_channel();
        let gecko = CoinGecko::new(api_key, update_tx, assets.clone());

        info!("Fetching prices...");
        gecko.update_prices().await.expect("Failed to fetch prices");

        let mut usd_prices = HashMap::new();

        info!("Processing messages...");
        while let Ok(msg) = update_rx.try_recv() {
            if let PriceOracleMessage::UpdateUsd { prices, .. } = msg {
                info!("Received USD prices update with {} prices", prices.len());
                for (coin, price) in prices {
                    info!("  {} -> ${}", coin, price);
                    usd_prices.insert(coin, price);
                }
            }
        }

        info!("\nFinal USD prices collected: {:?}", usd_prices);

        // Verify we got USD prices for all native coins and tokens
        for uid in assets.values() {
            let price = usd_prices.get(uid).copied().unwrap_or_else(|| {
                panic!("Missing USD price for {uid:?}. Got USD prices: {usd_prices:?}")
            });
            info!("Verified {} USD price: ${}", uid, price);
            assert!(price > 0.0, "Invalid USD price for {uid:?}: {price}");
        }

        println!("\nTest passed! All prices fetched successfully.");
    }
}
