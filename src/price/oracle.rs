use super::CoinGecko;
use crate::{
    price::{fetchers::PriceFetcher, metrics::CoinPairMetrics},
    types::{CoinKind, CoinPair, CoinRegistry},
};
use alloy::primitives::U256;
use metrics::counter;
use std::{
    collections::{HashMap, hash_map::Entry},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};
use tracing::{trace, warn};

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
    /// Message to update inner price registry.
    Update { fetcher: PriceFetcher, prices: Vec<(CoinPair, f64)>, timestamp: Instant },
    /// Message to lookup the conversion rate of [`CoinPair`].
    Lookup { pair: CoinPair, tx: oneshot::Sender<Option<f64>> },
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
#[derive(Debug)]
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
                    PriceOracleMessage::Update { fetcher, prices, timestamp } => {
                        trace!(?fetcher, ?timestamp, "Received price updates.");

                        for (pair, rate) in prices {
                            registry.insert(pair, RateTick { rate, timestamp });
                        }
                    }
                    PriceOracleMessage::Lookup { pair, tx } => {
                        trace!(?pair, "Received lookup request.");
                        let _ = tx.send(
                            registry
                                .get(&pair)
                                .filter(|t| {
                                    if t.timestamp.elapsed() > config.rate_ttl {
                                        warn!(?pair, "Hit expired price rate");
                                        counter!("price.expired_hits").increment(1);
                                        false
                                    } else {
                                        true
                                    }
                                })
                                .map(|t| t.rate),
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
    pub fn spawn_fetcher(
        &self,
        coin_registry: Arc<CoinRegistry>,
        fetcher: PriceFetcher,
        pairs: &[CoinPair],
    ) {
        match fetcher {
            PriceFetcher::CoinGecko => CoinGecko::launch(coin_registry, pairs, self.tx.clone()),
        }
    }

    /// Returns the conversion rate from a coin to native ETH (in wei).
    pub async fn eth_price(&self, coin: CoinKind) -> Option<U256> {
        let (req_tx, req_rx) = oneshot::channel();
        let _ = self.tx.send(PriceOracleMessage::Lookup {
            pair: CoinPair { from: coin, to: CoinKind::ETH },
            tx: req_tx,
        });
        req_rx
            .await
            .ok()
            .flatten()
            .or(self.constant_rate)
            .map(|eth_price| U256::from((eth_price * 1e18) as u128))
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
    inner: HashMap<CoinPair, CoinPairInfo>,
}

impl PriceRegistry {
    /// Inserts or updates the rate for the given pair
    fn insert(&mut self, pair: CoinPair, rate: RateTick) {
        match self.inner.entry(pair) {
            Entry::Occupied(mut e) => {
                e.get().metrics.rate.record(rate.rate);
                e.get_mut().rate = rate;
            }
            Entry::Vacant(e) => {
                let id = e.key().identifier();
                let info = CoinPairInfo {
                    metrics: CoinPairMetrics::new_with_labels(&[("pair", id)]),
                    rate,
                };
                info.metrics.rate.record(rate.rate);
                e.insert(info);
            }
        }
    }

    fn get(&self, pair: &CoinPair) -> Option<&RateTick> {
        self.inner.get(pair).map(|p| &p.rate)
    }
}
