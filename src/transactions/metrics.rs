use metrics::{Counter, Gauge, Histogram};
use metrics_derive::Metrics;

/// Metrics for a [`TransactionService`](crate::transactions::TransactionService).
#[derive(Metrics)]
#[metrics(scope = "transactions")]
pub struct TransactionServiceMetrics {
    /// Number of sent transactions.
    pub sent: Counter,
    /// Number of failed transactions.
    pub failed: Counter,
    /// Number of confirmed transactions
    pub confirmed: Counter,
    /// How many signers are currently active
    pub active_signers: Gauge,
    /// How many signers are currently paused
    pub paused_signers: Gauge,
    /// Number of pending transactions.
    pub pending: Gauge,
    /// Number of queued transactions.
    pub queued: Gauge,
    /// Time it takes to include transactions, in milliseconds.
    pub confirmation_time: Histogram,
    /// Number of closed nonce gaps
    pub closed_nonce_gaps: Counter,
}
