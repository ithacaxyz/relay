//! Price metrics

use metrics::{Counter, Gauge};
use metrics_derive::Metrics;

/// Metrics for a [`CoinPair`](crate::types::CoinPair).
#[derive(Metrics)]
#[metrics(scope = "oracle")]
pub struct CoinPairMetrics {
    /// Rate for this pair.
    pub rate: Gauge,
    /// How often an expired rate was requested.
    pub expired_hits: Counter,
}
