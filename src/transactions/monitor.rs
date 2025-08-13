use alloy::{
    primitives::B256,
    providers::{DynProvider, PendingTransactionConfig, Provider, ProviderBuilder},
    rpc::{client::ClientBuilder, types::TransactionReceipt},
    transports::TransportResult,
};
use alloy_chains::Chain;
use futures_util::{FutureExt, StreamExt, stream::FuturesUnordered};
use std::{pin::Pin, sync::Arc, time::Duration};
use url::Url;

use crate::{
    chains::RETRY_LAYER,
    config::TransactionServiceConfig,
    constants::DEFAULT_POLL_INTERVAL,
    transactions::flashblocks::{FlashblocksWatcher, FlashblocksWatcherHandle},
    transport::create_transport,
};

use super::metrics::TransactionServiceMetrics;
/// Handle to monitor transactions.
#[derive(Debug, Clone)]
pub struct TransactionMonitoringHandle {
    /// Network provider.
    provider: DynProvider,
    /// If relevant, the provider located close to sequencer that is expected to receive blocks
    /// faster than our node.
    external_provider: Option<DynProvider>,
    /// Flashblocks watcher handle, if relevant for the network.
    flashblocks_handle: Option<FlashblocksWatcherHandle>,
    /// Metrics for the monitor.
    metrics: Arc<TransactionServiceMetrics>,
}

impl TransactionMonitoringHandle {
    /// Creates a new [`TxMonitoringHandle`].
    pub async fn new(
        provider: DynProvider,
        flashblocks_rpc_endpoint: Option<&Url>,
        config: TransactionServiceConfig,
        metrics: Arc<TransactionServiceMetrics>,
    ) -> TransportResult<Self> {
        let chain = Chain::from_id(provider.get_chain_id().await?);

        let external_provider = if let Some(endpoint) = config.public_node_endpoints.get(&chain) {
            let (transport, is_local) = create_transport(endpoint).await?;
            let client = ClientBuilder::default()
                .layer(RETRY_LAYER)
                .transport(transport, is_local)
                .with_poll_interval(DEFAULT_POLL_INTERVAL);
            Some(ProviderBuilder::new().connect_client(client).erased())
        } else {
            None
        };

        let flashblocks_handle = if let Some(endpoint) = flashblocks_rpc_endpoint {
            let (flashblocks, handle) = FlashblocksWatcher::new(endpoint.clone()).await?;
            tokio::spawn(flashblocks.into_future());
            Some(handle)
        } else {
            None
        };

        Ok(Self { external_provider, provider, metrics, flashblocks_handle })
    }

    /// Attempts to wait for a transaction confirmation.
    pub async fn watch_transaction(
        &self,
        tx_hash: B256,
        timeout: Duration,
    ) -> Option<TransactionReceipt> {
        let config = PendingTransactionConfig::new(tx_hash).with_timeout(Some(timeout));

        let watch_with_provider = async |provider: &DynProvider, is_external: bool| {
            let is_confirmed =
                if let Ok(tx) = provider.watch_pending_transaction(config.clone()).await {
                    tx.await.is_ok()
                } else {
                    false
                };

            if is_confirmed
                && let Ok(Some(receipt)) = provider.get_transaction_receipt(tx_hash).await
            {
                if is_external {
                    self.metrics.external_confirmations.increment(1);
                } else {
                    self.metrics.local_confirmations.increment(1);
                }

                return Some(receipt);
            }

            None
        };

        let mut futures = core::iter::once(Box::pin(watch_with_provider(&self.provider, false))
            as Pin<Box<dyn Future<Output = _> + Send>>)
        .chain(self.external_provider.as_ref().map(|p| Box::pin(watch_with_provider(p, true)) as _))
        .chain(self.flashblocks_handle.as_ref().map(|h| {
            Box::pin(h.watch_transaction(tx_hash, timeout).map(|receipt| {
                receipt.inspect(|_| self.metrics.flashblock_confirmations.increment(1)).ok()
            })) as _
        }))
        .collect::<FuturesUnordered<_>>();

        while let Some(result) = futures.next().await {
            if let Some(receipt) = result {
                return Some(receipt);
            }
        }

        None
    }
}
