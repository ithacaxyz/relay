use crate::{
    constants::DEFAULT_POLL_INTERVAL,
    transport::{RETRY_LAYER, create_transport},
};
use alloy::{
    eips::BlockId,
    primitives::{B256, map::HashMap},
    providers::{DynProvider, Provider, ProviderBuilder},
    rpc::{
        client::{ClientBuilder, PollerBuilder},
        types::{Block, BlockTransactions, TransactionReceipt},
    },
    transports::TransportResult,
};
use futures_util::{Stream, StreamExt};
use std::{collections::BTreeMap, pin::Pin, time::Duration};
use tokio::{
    sync::{mpsc, oneshot},
    time::{Instant, sleep_until},
};
use url::Url;

/// A request to watch a transaction.
pub struct WatchTxRequest {
    /// The transaction hash to watch.
    tx_hash: B256,
    /// Timeout after which transaction should no longer be tracked.
    timeout: Duration,
    /// Sender half of the transaction receipt channel.
    tx: oneshot::Sender<TransactionReceipt>,
}

/// Handle to a spawned [`FlashblocksWatcher`].
#[derive(Debug, Clone)]
pub struct FlashblocksWatcherHandle {
    requests_tx: mpsc::UnboundedSender<WatchTxRequest>,
}

impl FlashblocksWatcherHandle {
    /// Returns a future that resolves to the transaction receipt if transaction was included in a
    /// flashblock.
    pub fn watch_transaction(
        &self,
        tx_hash: B256,
        timeout: Duration,
    ) -> oneshot::Receiver<TransactionReceipt> {
        let (tx, rx) = oneshot::channel();
        let _ = self.requests_tx.send(WatchTxRequest { tx_hash, timeout, tx });

        rx
    }
}

/// Flashblocks watcher.
#[must_use = "futures do nothing unless polled"]
pub struct FlashblocksWatcher<S> {
    /// Receivers for pending transactions notified on confirmation.
    pending: HashMap<B256, oneshot::Sender<TransactionReceipt>>,
    /// Ordered map of transactions to reap at a certain time.
    reap_at: BTreeMap<Instant, B256>,
    /// Transaction watching requests stream.
    requests_rx: mpsc::UnboundedReceiver<WatchTxRequest>,
    /// Provider to use for flashblocks.
    provider: DynProvider,
    /// Stream of flashblocks
    flashblocks: S,
}

impl FlashblocksWatcher<()> {
    pub async fn new(
        endpoint: Url,
    ) -> TransportResult<(
        FlashblocksWatcher<impl Stream<Item = Vec<B256>>>,
        FlashblocksWatcherHandle,
    )> {
        let (requests_tx, requests_rx) = mpsc::unbounded_channel();

        let provider = {
            let (transport, is_local) = create_transport(&endpoint).await?;
            let client = ClientBuilder::default()
                .layer(RETRY_LAYER)
                .transport(transport, is_local)
                .with_poll_interval(DEFAULT_POLL_INTERVAL);
            ProviderBuilder::new().connect_client(client).erased()
        };

        let flashblocks = PollerBuilder::<_, Block>::new(
            provider.weak_client(),
            "eth_getBlockByNumber",
            (BlockId::pending(), false),
        )
        .spawn()
        .into_stream()
        .map(|block| {
            let BlockTransactions::Hashes(hashes) = block.transactions.into_hashes() else {
                unreachable!()
            };
            hashes
        });

        let this = FlashblocksWatcher {
            pending: Default::default(),
            reap_at: Default::default(),
            requests_rx,
            provider,
            flashblocks,
        };

        Ok((this, FlashblocksWatcherHandle { requests_tx }))
    }
}

impl<S: Stream<Item = Vec<B256>> + Send + Unpin + 'static> IntoFuture for FlashblocksWatcher<S> {
    type Output = ();
    type IntoFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

    fn into_future(mut self) -> Self::IntoFuture {
        Box::pin(async move {
            loop {
                let sleep = sleep_until(
                    self.reap_at
                        .first_key_value()
                        .map(|(k, _)| *k)
                        .unwrap_or_else(|| Instant::now() + Duration::from_secs(60)),
                );
                tokio::select! {
                    // handle new requests
                    maybe_request = self.requests_rx.recv() => {
                        let Some(WatchTxRequest { tx_hash, timeout, tx }) = maybe_request else {
                            break // all handles dropped
                        };

                        self.pending.insert(tx_hash, tx);
                        self.reap_at.insert(Instant::now() + timeout, tx_hash);
                    }
                    // handle new flashblocks
                    Some(txs) = self.flashblocks.next() => {
                        for tx_hash in txs {
                            // if transaction is confirmed, spawn a task to fetch its receipt and send it back to the requester
                            if let Some(tx) = self.pending.remove(&tx_hash) {
                                let receipt_future = self.provider.get_transaction_receipt(tx_hash);
                                tokio::spawn(async move {
                                    if let Ok(Some(receipt)) = receipt_future.await {
                                        let _ = tx.send(receipt);
                                    }
                                });
                            }
                        }
                    }
                    // Ensures that we always handle timeouts.
                    _ = sleep => {},
                }

                // Reap timeouts
                let to_keep = self.reap_at.split_off(&Instant::now());
                let to_reap = std::mem::replace(&mut self.reap_at, to_keep);

                for tx_hash in to_reap.values() {
                    self.pending.remove(tx_hash);
                }
            }
        })
    }
}
