use super::CoinGecko;
use crate::{
    price::fetchers::PriceFetcher,
    types::{CoinKind, CoinPair},
};
use alloy::primitives::U256;
use std::collections::HashMap;
use tokio::sync::{mpsc, oneshot};
use tracing::trace;

/// Coin pair rate taken a certain timestamp.
#[derive(Debug, Clone, Copy)]
struct RateTick {
    /// Price rate.
    pub rate: f64,
    /// Timestamp when we received the rate update.
    #[allow(unused)]
    pub timestamp: u64,
}

/// Messages used by the price oracle task.
#[derive(Debug)]
pub enum PriceOracleMessage {
    /// Message to update inner price registry.
    Update { fetcher: PriceFetcher, prices: Vec<(CoinPair, f64)>, timestamp: u64 },
    /// Message to lookup the conversion rate of [`CoinPair`].
    Lookup { pair: CoinPair, tx: oneshot::Sender<Option<f64>> },
}

/// A price orable that can be used to lookup or update the price of a [`CoinPair`].
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
        Self::new()
    }
}

impl PriceOracle {
    /// Return a new [`PriceOracle`].
    pub fn new() -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut registry: HashMap<CoinPair, RateTick> = HashMap::new();
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
                        let _ = tx.send(registry.get(&pair).map(|t| t.rate));
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

    /// Spawns a price fetcher with a [`CoinKind`] list.
    pub fn spawn_fetcher(&self, fetcher: PriceFetcher, pairs: &[CoinPair]) {
        match fetcher {
            PriceFetcher::CoinGecko => CoinGecko::launch(pairs, self.tx.clone()),
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
