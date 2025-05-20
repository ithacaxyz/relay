use alloy::{
    primitives::B256,
    providers::{DynProvider, PendingTransactionConfig, Provider},
    transports::TransportResult,
};
use futures_util::{StreamExt, stream::FuturesUnordered};
use std::time::Duration;

/// Handle to monitor transactions.
#[derive(Debug, Clone)]
pub struct TxMonitoringHandle {
    /// Network provider.
    provider: DynProvider,
    /// If relevant, the provider located close to sequencer that is expected to receive blocks
    /// faster than our node.
    external_provider: Option<DynProvider>,
}

impl TxMonitoringHandle {
    /// Creates a new [`TxMonitoringHandle`].
    pub async fn new(
        provider: DynProvider,
        external_provider: Option<DynProvider>,
    ) -> TransportResult<Self> {
        Ok(Self { external_provider, provider })
    }

    /// Attempts to wait for a transaction confirmation.
    pub async fn watch_transaction(&self, tx_hash: B256, timeout: Duration) -> Option<B256> {
        let config = PendingTransactionConfig::new(tx_hash).with_timeout(Some(timeout));

        let watch_with_provider = async |provider: &DynProvider| {
            if let Ok(tx) = provider.watch_pending_transaction(config.clone()).await {
                tx.await.is_ok()
            } else {
                false
            }
        };

        let mut futures = core::iter::once(Box::pin(watch_with_provider(&self.provider)))
            .chain(self.external_provider.as_ref().map(|p| Box::pin(watch_with_provider(p))))
            .collect::<FuturesUnordered<_>>();

        while let Some(result) = futures.next().await {
            if result {
                return Some(tx_hash);
            }
        }

        None
    }
}
