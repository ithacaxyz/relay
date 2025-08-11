use crate::{
    error::{QuoteError, RelayError},
    price::{PriceFetcher, oracle::PriceOracleMessage},
    types::CoinKind,
};
use itertools::Itertools;
use metrics::counter;
use std::{
    collections::HashMap,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use strum::IntoEnumIterator;
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
}

impl CoinGecko {
    /// Creates a new [`CoinGecko`] instance.
    pub fn new(api_key: String, update_tx: mpsc::UnboundedSender<PriceOracleMessage>) -> Self {
        let ids = CoinKind::iter().map(Self::coin_kind_to_id).join(",");

        let url = format!(
            "https://pro-api.coingecko.com/api/v3/simple/price?ids={ids}&vs_currencies=usd&x_cg_pro_api_key={api_key}",
        );

        Self { url, update_tx }
    }

    /// Creates an instance of [`CoinGecko`] that sends a price feed to [`PriceOracle`] for all
    /// tokens from a spawned task every 10 seconds.
    pub fn launch(update_tx: mpsc::UnboundedSender<PriceOracleMessage>) {
        if Self::api_key().is_empty() {
            warn!("GECKO_API environment variable not set, CoinGecko price fetcher will not run");
            return;
        }

        let gecko = Self::new(Self::api_key(), update_tx);

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

    /// Maps [`CoinKind`] to CoinGecko API ID.
    fn coin_kind_to_id(kind: CoinKind) -> &'static str {
        match kind {
            CoinKind::USDC => "usd-coin",
            CoinKind::USDT => "tether",
            CoinKind::ETH => "ethereum",
            CoinKind::BNB => "binancecoin",
            CoinKind::POL => "matic-network",
            CoinKind::EXP1 => "usd-coin",
            CoinKind::EXP2 => "usd-coin",
        }
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

        let prices = CoinKind::iter()
            .filter_map(|kind| {
                let id = Self::coin_kind_to_id(kind);
                let price = *data.get(id).and_then(|prices| prices.get("usd"))?;
                trace!(
                    token = ?kind,
                    usd_price = price,
                    "Fetched USD price for token"
                );
                Some((kind, price))
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

        let (update_tx, mut update_rx) = mpsc::unbounded_channel();
        let gecko = CoinGecko::new(api_key, update_tx);

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

        // Verify we got USD prices for all native coins (ETH, BNB, POL) and tokens
        for coin in CoinKind::iter() {
            let price = usd_prices.get(&coin).copied().unwrap_or_else(|| {
                panic!("Missing USD price for {coin:?}. Got USD prices: {usd_prices:?}")
            });
            info!("Verified {} USD price: ${}", coin, price);
            assert!(price > 0.0, "Invalid USD price for {coin:?}: {price}");
        }

        println!("\nTest passed! All prices fetched successfully.");
    }
}
