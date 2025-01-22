use metrics::Counter;
use metrics_derive::Metrics;

/// Metrics for the `wallet_` RPC namespace.
#[derive(Metrics)]
#[metrics(scope = "wallet")]
pub struct WalletMetrics {
    /// Number of invalid calls to `odyssey_sendTransaction`
    pub invalid_send_transaction_calls: Counter,
    /// Number of valid calls to `odyssey_sendTransaction`
    pub valid_send_transaction_calls: Counter,
}
