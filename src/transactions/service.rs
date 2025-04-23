use super::{
    Signer, SignerEvent, SignerId, SignerTask, TxId,
    metrics::TransactionServiceMetrics,
    transaction::{RelayTransaction, TransactionStatus},
};
use crate::{
    config::TransactionServiceConfig,
    error::StorageError,
    signers::DynSigner,
    storage::{RelayStorage, StorageApi},
};
use alloy::providers::{DynProvider, Provider};
use futures_util::{StreamExt, stream::FuturesUnordered};
use std::{
    collections::{HashMap, VecDeque},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Messages accepted by the [`TransactionService`].
#[derive(Debug)]
pub enum TransactionServiceMessage {
    /// Message to send a transaction and receive events about the status of the transaction.
    SendTransaction(RelayTransaction, mpsc::UnboundedSender<TransactionStatus>),
}

/// Handle to communicate with the [`TransactionService`].
#[derive(Debug, Clone)]
pub struct TransactionServiceHandle {
    storage: RelayStorage,
    command_tx: mpsc::UnboundedSender<TransactionServiceMessage>,
}

impl TransactionServiceHandle {
    /// Writes transaction to queue and sends it to transaction service.
    pub async fn send_transaction(
        &self,
        tx: RelayTransaction,
    ) -> Result<mpsc::UnboundedReceiver<TransactionStatus>, StorageError> {
        self.storage.write_queued_transaction(&tx).await?;
        let (status_tx, status_rx) = mpsc::unbounded_channel();
        let _ = self.command_tx.send(TransactionServiceMessage::SendTransaction(tx, status_tx));
        Ok(status_rx)
    }
}

/// Service that handles transactions by dispatching outgoing transaction to an available signer and
/// monitors the state of the transaction.
/// Receives incoming [`RelayTransaction`] requests and routes them to an available signer.
#[derive(derive_more::Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct TransactionService {
    /// Handles of _all_ available signers responsible for broadcasting transactions.
    ///
    /// This forms a bijection with {active,paused} signers, meaning each signer id is either
    /// `active` OR `paused`.
    signers: FuturesUnordered<SignerTask>,
    /// Configuration for the service.
    config: TransactionServiceConfig,
    /// Signers we currently can use to dispatch _new_ requests to.
    active_signers: Vec<SignerId>,
    /// Signers that are currently paused until re-activated.
    paused_signers: Vec<SignerId>,
    /// Tracks unique identifiers for signers
    signer_id: u64,
    /// Signer event channel
    to_service: mpsc::UnboundedSender<SignerEvent>,
    /// Message channel from signers to this service.
    from_signers: mpsc::UnboundedReceiver<SignerEvent>,
    /// Incoming messages for the service.
    command_rx: mpsc::UnboundedReceiver<TransactionServiceMessage>,
    /// Subscriptions to transaction status updates back to the initiator of the transaction.
    ///
    /// This keeps a holistic view of all active transactions.
    // TODO: should we even maintain this here or directly wire it in the signer.
    subscriptions: HashMap<TxId, mpsc::UnboundedSender<TransactionStatus>>,
    /// Metrics of the service.
    metrics: Arc<TransactionServiceMetrics>,
    /// Queue of transactions waiting for signers capacity.
    queue: VecDeque<RelayTransaction>,
}

impl TransactionService {
    /// Creates a new [`TransactionService`].
    ///
    /// This also spawns dedicated [`Signer`] task for each configured signer.
    pub async fn new(
        provider: DynProvider,
        signers: Vec<DynSigner>,
        storage: RelayStorage,
        config: TransactionServiceConfig,
    ) -> eyre::Result<(Self, TransactionServiceHandle)> {
        let chain_id = provider.get_chain_id().await?;
        let metrics = Arc::new(TransactionServiceMetrics::new_with_labels(&[(
            "chain_id",
            chain_id.to_string(),
        )]));
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let (to_service, from_signers) = mpsc::unbounded_channel();

        let queue = storage.read_queued_transactions(chain_id).await?;

        let mut this = Self {
            signers: Default::default(),
            config,
            active_signers: vec![],
            paused_signers: vec![],
            signer_id: 0,
            to_service,
            from_signers,
            command_rx,
            subscriptions: Default::default(),
            metrics,
            queue: queue.into(),
        };

        // crate all the signers
        for signer in signers {
            this.create_signer(signer, storage.clone(), provider.clone()).await?;
        }

        let handle = TransactionServiceHandle { command_tx, storage };

        Ok((this, handle))
    }

    /// Creates a new [`Signer`] instance and spawns it.
    async fn create_signer(
        &mut self,
        signer: DynSigner,
        storage: RelayStorage,
        provider: DynProvider,
    ) -> eyre::Result<()> {
        let signer_id = self.next_signer_id();
        debug!(%signer_id, "creating new signer");
        let metrics = self.metrics.clone();
        let events_tx = self.to_service.clone();
        let signer = Signer::new(
            signer_id,
            provider,
            signer,
            storage,
            events_tx,
            metrics,
            self.config.clone(),
        )
        .await?;
        let task = signer.into_future().await?;

        // track new signer
        self.insert_active_signer(signer_id, task);

        Ok(())
    }

    /// Adds a _new_ signer.
    fn insert_active_signer(&mut self, id: SignerId, signer: SignerTask) {
        self.active_signers.push(id);
        self.signers.push(signer);
        self.update_signer_metrics();
    }

    /// Returns the next unique signer id.
    fn next_signer_id(&mut self) -> SignerId {
        let id = self.signer_id;
        self.signer_id += 1;
        SignerId::new(id)
    }

    /// Moves a signer from paused to active if it is currently paused
    fn activate_signer(&mut self, signer_id: SignerId) {
        if let Some(pos) = self.paused_signers.iter().position(|id| *id == signer_id) {
            debug!(%signer_id, "activate signer");

            debug_assert!(
                self.is_paused_signer(&signer_id),
                "signer is still paused {:?}; duplicate entry",
                signer_id
            );
            debug_assert!(
                !self.is_active_signer(&signer_id),
                "signer is already active {:?}",
                signer_id
            );

            // remove signer from paused
            self.paused_signers.remove(pos);
            // activate signer
            self.active_signers.push(signer_id);

            self.update_signer_metrics();
        }
    }

    /// Moves a signer from active to paused if it is currently active
    fn pause_signer(&mut self, signer_id: SignerId) {
        if let Some(pos) = self.active_signers.iter().position(|id| *id == signer_id) {
            debug!(%signer_id, "pausing signer");

            debug_assert!(
                self.is_active_signer(&signer_id),
                "signer is still active {:?}; duplicate entry",
                signer_id
            );
            debug_assert!(
                !self.is_paused_signer(&signer_id),
                "signer is already paused {:?}",
                signer_id
            );

            // remove signer from active
            self.active_signers.remove(pos);
            // pause signer
            self.paused_signers.push(signer_id);

            self.update_signer_metrics();
        }
    }

    fn update_signer_metrics(&self) {
        self.metrics.active_signers.set(self.active_signers.len() as f64);
        self.metrics.paused_signers.set(self.paused_signers.len() as f64);
    }

    /// Returns true if the given signer is currently active.
    fn is_active_signer(&self, signer_id: &SignerId) -> bool {
        self.active_signers.contains(signer_id)
    }

    /// Returns true if the given signer is currently paused.
    fn is_paused_signer(&self, signer_id: &SignerId) -> bool {
        self.paused_signers.contains(signer_id)
    }

    /// Picks the best signer for dispatching a transaction. Signer with the highest capacity is
    /// returned.
    fn best_signer(&self) -> Option<&SignerTask> {
        let mut best_signer = None;
        let mut best_capacity = 0;
        let mut total_pending = 0;

        for signer in self.signers.iter() {
            let capacity = signer.capacity();
            if capacity > best_capacity {
                best_signer = Some(signer);
                best_capacity = capacity;
            }

            total_pending += signer.pending();
        }

        best_signer.filter(|_| total_pending < self.config.max_pending_transactions)
    }

    /// Sends the given transaction to an available signer.
    fn send_transaction(
        &mut self,
        tx: RelayTransaction,
        status_tx: mpsc::UnboundedSender<TransactionStatus>,
    ) {
        debug_assert!(!self.active_signers.is_empty());
        debug_assert!(
            !self.subscriptions.contains_key(&tx.id),
            "tx subscription already exists {}",
            tx.id
        );

        self.subscriptions.insert(tx.id, status_tx);

        if let Some(signer) = self.best_signer() {
            signer.push_transaction(tx);
            self.metrics.sent.increment(1);
        } else {
            warn!("no signers available, enqueueing transaction for later");
            self.queue.push_back(tx);
            self.metrics.queued.increment(1);
        }
    }

    /// Attempts advancing the queue by sending a transaction to an available signer.
    ///
    /// Returns `true` if any transaction was sent.
    fn advance_queue(&mut self) {
        while let Some(tx) = self.queue.pop_front() {
            if let Some(signer) = self.best_signer() {
                signer.push_transaction(tx);
                self.metrics.sent.increment(1);
                self.metrics.queued.decrement(1);
            } else {
                self.queue.push_front(tx);
                break;
            }
        }
    }
}

impl Future for TransactionService {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let instant = Instant::now();

        let this = self.get_mut();

        // Advance signers
        let _ = this.signers.poll_next_unpin(cx);

        // Try advancing the queue.
        this.advance_queue();

        // drain all commands
        while let Poll::Ready(action_opt) = this.command_rx.poll_recv(cx) {
            if let Some(action) = action_opt {
                match action {
                    TransactionServiceMessage::SendTransaction(tx, status_tx) => {
                        this.send_transaction(tx, status_tx);
                    }
                }
            } else {
                // command channel closed, shut down
                debug!("command channel closed");
                return Poll::Ready(());
            }
        }

        // drain messages from signers
        while let Poll::Ready(Some(event)) = this.from_signers.poll_recv(cx) {
            match event {
                SignerEvent::TransactionStatus(id, status) => {
                    match &status {
                        TransactionStatus::Failed(err) => {
                            debug!(tx_id = %id, %err, "transaction failed");
                            this.metrics.failed.increment(1);
                        }
                        TransactionStatus::Confirmed(hash) => {
                            debug!(tx_id = %id, %hash, "transaction confirmed");
                            this.metrics.confirmed.increment(1);
                        }
                        _ => {}
                    }

                    if let Some(status_tx) = this.subscriptions.get(&id) {
                        let _ = status_tx.send(status.clone());
                    }

                    if status.is_final() {
                        this.subscriptions.remove(&id);
                    }
                }
                SignerEvent::PauseSigner(id) => {
                    this.pause_signer(id);
                }
                SignerEvent::ReActive(id) => {
                    this.activate_signer(id);
                }
            }
        }

        this.metrics.poll_duration.record(instant.elapsed().as_nanos() as f64);

        Poll::Pending
    }
}
