use alloy::primitives::U256;
use metrics::{Counter, Histogram};
use metrics_derive::Metrics;

/// Chain specific metrics for the layerzero settler.
#[derive(Metrics)]
#[metrics(scope = "layerzero")]
pub struct LayerZeroChainMetrics {
    /// Cumulative layerzero fees paid on this chain
    cumulative_fees_paid: Counter,
    /// Histogram for the native fees paid on this chain
    fees_paid_histogram: Histogram,
}

impl LayerZeroChainMetrics {
    /// Record native fee paid for layerzero
    pub fn record_fee_paid(&self, fee: U256) {
        self.fees_paid_histogram.record(f64::from(fee));
        if let Ok(fee) = fee.try_into() {
            self.cumulative_fees_paid.increment(fee);
        }
    }
}
