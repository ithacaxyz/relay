use metrics::{Counter, Gauge, Histogram};
use metrics_derive::Metrics;

#[derive(Metrics)]
#[metrics(scope = "transactions")]
pub struct TransactionServiceMetrics {
    /// Number of sent transactions.
    pub sent: Counter,
    /// Number of failed transactions.
    pub failed: Counter,
    /// Number of confirmed transactions
    pub confirmed: Counter,
    /// Number of pending transactions.
    pub pending: Gauge,
    /// Time it takes to include transactions, in seconds.
    pub confirmation_time: Histogram,
}
