//! Price metrics

use metrics::Gauge;
use metrics_derive::Metrics;

/// Metrics for a [`CoinPair`](crate::types::CoinPair).
#[derive(Metrics)]
#[metrics(scope = "oracle")]
pub struct CoinPairMetrics {
    /// Rate for this pair.
    pub rate: Gauge,
}
