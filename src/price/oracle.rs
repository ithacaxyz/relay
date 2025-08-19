use super::{CoinGecko, DeFiLlama};
use crate::{
    config::RelayConfig,
    price::{fetchers::PriceFetcher, metrics::CoinPairMetrics},
    types::AssetUid,
};
use alloy::primitives::U256;
use std::{
    collections::{HashMap, hash_map::Entry},
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};
use tracing::trace;

/// Coin pair rate taken a certain timestamp.
#[derive(Debug, Clone, Copy)]
struct RateTick {
    /// Price rate.
    pub rate: f64,
    /// Timestamp when we received the rate update.
    pub timestamp: Instant,
}

/// Messages used by the price oracle task.
#[derive(Debug)]
pub enum PriceOracleMessage {
    /// Message to update USD prices.
    UpdateUsd { fetcher: PriceFetcher, prices: Vec<(AssetUid, f64)>, timestamp: Instant },
    /// Message to lookup the conversion rate of the given pair.
    Lookup { from: AssetUid, to: AssetUid, tx: oneshot::Sender<Option<f64>> },
    /// Message to lookup the USD price of a coin.
    LookupUsd { uid: AssetUid, tx: oneshot::Sender<Option<f64>> },
}

/// Configuration for the price oracle.
#[derive(Debug, Clone)]
pub struct PriceOracleConfig {
    /// Duration after which a rate is considered expired.
    pub rate_ttl: Duration,
}

impl Default for PriceOracleConfig {
    fn default() -> Self {
        Self { rate_ttl: Duration::from_secs(300) }
    }
}

/// A price oracle that can be used to lookup or update the price of a [`CoinPair`].
#[derive(Debug, Clone)]
pub struct PriceOracle {
    /// Channel sender to lookup and update pair prices.
    tx: mpsc::UnboundedSender<PriceOracleMessage>,
    /// Constant rate which will be the fallback on a lookup that does not return a price. For
    /// testing only.
    constant_rate: Option<f64>,
}

impl Default for PriceOracle {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

impl PriceOracle {
    /// Return a new [`PriceOracle`].
    pub fn new(config: PriceOracleConfig) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut registry = PriceRegistry::default();
            while let Some(message) = rx.recv().await {
                match message {
                    PriceOracleMessage::UpdateUsd { fetcher, prices, timestamp } => {
                        trace!(?fetcher, ?timestamp, "Received USD price updates.");

                        for (coin, rate) in prices {
                            trace!(
                                coin = ?coin,
                                usd_price = rate,
                                "USD price update"
                            );
                            registry.insert_usd(coin, RateTick { rate, timestamp });
                        }
                    }
                    PriceOracleMessage::Lookup { from, to, tx } => {
                        trace!(?from, ?to, "Received lookup request.");
                        let rate = registry
                            .get_usd(&from)
                            .and_then(|usd_from| Some((usd_from, registry.get_usd(&to)?)))
                            .filter(|(usd_from, usd_to)| {
                                if usd_from.rate.timestamp.elapsed() > config.rate_ttl {
                                    usd_from.metrics.expired_hits.increment(1);
                                    false
                                } else if usd_to.rate.timestamp.elapsed() > config.rate_ttl {
                                    usd_to.metrics.expired_hits.increment(1);
                                    false
                                } else {
                                    true
                                }
                            })
                            .map(|(usd_from, usd_to)| usd_from.rate.rate / usd_to.rate.rate);

                        let _ = tx.send(rate);
                    }
                    PriceOracleMessage::LookupUsd { uid, tx } => {
                        trace!(?uid, "Received USD lookup request.");
                        let _ = tx.send(
                            registry
                                .get_usd(&uid)
                                .filter(|info| {
                                    if info.rate.timestamp.elapsed() > config.rate_ttl {
                                        info.metrics.expired_hits.increment(1);
                                        false
                                    } else {
                                        true
                                    }
                                })
                                .map(|info| info.rate.rate),
                        );
                    }
                }
            }
        });

        Self { tx, constant_rate: None }
    }

    /// Returns [`Self`] with a constant rate to fallback to.
    pub fn with_constant_rate(mut self, rate: f64) -> Self {
        self.constant_rate = Some(rate);
        self
    }

    /// Spawns a price fetcher with a [`CoinPair`] list.
    pub fn spawn_fetcher(&self, fetcher: PriceFetcher, config: &RelayConfig) {
        match fetcher {
            PriceFetcher::CoinGecko => CoinGecko::launch(self.tx.clone(), config),
            PriceFetcher::DeFiLlama => {
                if config.pricefeed.defillama.enabled {
                    DeFiLlama::launch(self.tx.clone(), config)
                }
            }
        }
    }

    /// Returns the conversion rate from an asset to a native asset.
    ///
    /// # Note
    ///
    /// This assumes the native asset (`to`) uses 18 decimals.
    pub async fn native_conversion_rate(
        &self,
        asset_uid: AssetUid,
        native_uid: AssetUid,
    ) -> Option<U256> {
        if asset_uid == native_uid {
            return Some(U256::from(1e18));
        }

        let (req_tx, req_rx) = oneshot::channel();
        let _ = self.tx.send(PriceOracleMessage::Lookup {
            from: asset_uid,
            to: native_uid,
            tx: req_tx,
        });
        req_rx
            .await
            .ok()
            .flatten()
            .or(self.constant_rate)
            .map(|native_price| U256::from((native_price * 1e18) as u128))
    }

    /// Returns the conversion rate from a coin to USD.
    pub async fn usd_price(&self, uid: AssetUid) -> Option<f64> {
        let (req_tx, req_rx) = oneshot::channel();

        let _ = self.tx.send(PriceOracleMessage::LookupUsd { uid, tx: req_tx });
        req_rx.await.ok().flatten().or(self.constant_rate)
    }
}

/// Tracks values for the pair
#[derive(Debug)]
struct CoinPairInfo {
    /// metrics for this pair
    metrics: CoinPairMetrics,
    /// The tracked rate
    rate: RateTick,
}

/// Keeps track of coin pairs and their rate
#[derive(Debug, Default)]
struct PriceRegistry {
    usd_prices: HashMap<AssetUid, CoinPairInfo>,
}

impl PriceRegistry {
    /// Inserts or updates the USD rate for the given coin
    fn insert_usd(&mut self, uid: AssetUid, rate: RateTick) {
        match self.usd_prices.entry(uid.clone()) {
            Entry::Occupied(mut e) => {
                e.get().metrics.rate.set(rate.rate);
                e.get_mut().rate = rate;
            }
            Entry::Vacant(e) => {
                let pair_id = format!("{uid}/USD");
                let info = CoinPairInfo {
                    metrics: CoinPairMetrics::new_with_labels(&[("pair", pair_id)]),
                    rate,
                };
                info.metrics.rate.set(rate.rate);
                e.insert(info);
            }
        }
    }

    /// Gets the USD rate for the given coin
    fn get_usd(&self, uid: &AssetUid) -> Option<&CoinPairInfo> {
        self.usd_prices.get(uid)
    }
}
