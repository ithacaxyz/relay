use alloy::primitives::Address;
use metrics::{Counter, Gauge, Histogram, counter, gauge, histogram};
use metrics_derive::Metrics;
use std::sync::Arc;

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
    /// Number of times we've replaced transactions.
    pub replacements_sent: Counter,
    /// Duration of polling the transaction service, in nanoseconds.
    pub poll_duration: Histogram,
    /// Number of user ops that landed on chain and succeeded.
    pub successful_user_ops: Counter,
    /// Number of user ops that landed on chain but failed.
    pub failed_user_ops: Counter,
}

/// Metrics of an individual signer, should be labeled with the signer address and chain ID.
#[derive(derive_more::Deref, Debug)]
pub struct SignerMetrics {
    /// Reference to the [`TransactionServiceMetrics`].
    #[deref]
    pub tx_metrics: Arc<TransactionServiceMetrics>,
    /// Time it takes to include transactions, in milliseconds.
    pub confirmation_time: Histogram,
    /// Number of detected nonce gaps
    pub detected_nonce_gaps: Counter,
    /// Number of closed nonce gaps
    pub closed_nonce_gaps: Counter,
    /// Duration of polling the signer task, in nanoseconds.
    pub poll_duration: Histogram,
    /// Gas spent on transactions.
    pub gas_spent: Gauge,
    /// Native spent on transactions.
    pub native_spent: Gauge,
    /// Signer nonce.
    pub nonce: Counter,
}

impl SignerMetrics {
    /// Creates a new [`SignerMetrics`] for the given signer address and chain.
    pub fn new(
        tx_metrics: Arc<TransactionServiceMetrics>,
        address: Address,
        chain_id: u64,
    ) -> Self {
        Self {
            tx_metrics,
            confirmation_time: histogram!("signer.confirmation_time", "address" => address.to_string(), "chain_id" => chain_id.to_string()),
            detected_nonce_gaps: counter!("signer.detected_nonce_gaps", "address" => address.to_string(), "chain_id" => chain_id.to_string()),
            closed_nonce_gaps: counter!("signer.closed_nonce_gaps", "address" => address.to_string(), "chain_id" => chain_id.to_string()),
            poll_duration: histogram!("signer.poll_duration", "address" => address.to_string(), "chain_id" => chain_id.to_string()),
            gas_spent: gauge!("signer.gas_spent", "address" => address.to_string(), "chain_id" => chain_id.to_string()),
            native_spent: gauge!("signer.native_spent", "address" => address.to_string(), "chain_id" => chain_id.to_string()),
            nonce: counter!("signer.nonce", "address" => address.to_string(), "chain_id" => chain_id.to_string()),
        }
    }
}
