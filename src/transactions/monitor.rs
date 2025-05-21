use alloy::{
    primitives::B256,
    providers::{DynProvider, PendingTransactionConfig, Provider},
};
use futures_util::{StreamExt, stream::FuturesUnordered};
use std::{sync::Arc, time::Duration};

use super::metrics::TransactionServiceMetrics;
/// Handle to monitor transactions.
#[derive(Debug, Clone)]
pub struct TransactionMonitoringHandle {
    /// Network provider.
    provider: DynProvider,
    /// If relevant, the provider located close to sequencer that is expected to receive blocks
    /// faster than our node.
    external_provider: Option<DynProvider>,
    /// Metrics for the monitor.
    metrics: Arc<TransactionServiceMetrics>,
}

impl TransactionMonitoringHandle {
    /// Creates a new [`TxMonitoringHandle`].
    pub fn new(
        provider: DynProvider,
        external_provider: Option<DynProvider>,
        metrics: Arc<TransactionServiceMetrics>,
    ) -> Self {
        Self { external_provider, provider, metrics }
    }

    /// Attempts to wait for a transaction confirmation.
    pub async fn watch_transaction(&self, tx_hash: B256, timeout: Duration) -> Option<B256> {
        let config = PendingTransactionConfig::new(tx_hash).with_timeout(Some(timeout));

        let watch_with_provider = async |provider: &DynProvider, is_external: bool| {
            let is_confirmed =
                if let Ok(tx) = provider.watch_pending_transaction(config.clone()).await {
                    tx.await.is_ok()
                } else {
                    false
                };

            if is_confirmed {
                if is_external {
                    self.metrics.external_confirmations.increment(1);
                } else {
                    self.metrics.local_confirmations.increment(1);
                }
            }

            is_confirmed
        };

        let mut futures = core::iter::once(Box::pin(watch_with_provider(&self.provider, false)))
            .chain(self.external_provider.as_ref().map(|p| Box::pin(watch_with_provider(p, true))))
            .collect::<FuturesUnordered<_>>();

        while let Some(result) = futures.next().await {
            if result {
                return Some(tx_hash);
            }
        }

        None
    }
}
