use super::{
    Signer, SignerEvent, SignerId, SignerTask, TransactionMonitoringHandle, TxId,
    metrics::TransactionServiceMetrics,
    transaction::{RelayTransaction, TransactionStatus},
};
use crate::{
    config::TransactionServiceConfig,
    constants::DEFAULT_POLL_INTERVAL,
    error::StorageError,
    signers::DynSigner,
    spawn::RETRY_LAYER,
    storage::{RelayStorage, StorageApi},
    transport::create_transport,
};
use alloy::{
    primitives::Address,
    providers::{DynProvider, Provider, ProviderBuilder},
    rpc::client::ClientBuilder,
};
use alloy_chains::Chain;
use futures_util::{StreamExt, stream::FuturesUnordered};
use rand::seq::SliceRandom;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};
use tokio::{sync::mpsc, task::JoinSet};
use tracing::{debug, error};

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
    ///
    /// Each received transaction must hit this queue first, and then popped from it via
    /// [`TxQueue::pop_ready`] to be sent to a signer.
    queue: TxQueue,
    /// Storage of the relay.
    storage: RelayStorage,
    /// Set of spawned tasks that are terminated when the service is dropped.
    tasks: JoinSet<Result<(), StorageError>>,
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

        let external_provider =
            if let Some(endpoint) = config.public_node_endpoints.get(&Chain::from_id(chain_id)) {
                let (transport, is_local) = create_transport(endpoint).await?;
                let client = ClientBuilder::default()
                    .layer(RETRY_LAYER)
                    .transport(transport, is_local)
                    .with_poll_interval(DEFAULT_POLL_INTERVAL);
                Some(ProviderBuilder::new().connect_client(client).erased())
            } else {
                None
            };

        let monitor = TransactionMonitoringHandle::new(
            provider.clone(),
            external_provider.clone(),
            metrics.clone(),
        );

        let mut this = Self {
            signers: Default::default(),
            active_signers: vec![],
            paused_signers: vec![],
            signer_id: 0,
            to_service,
            from_signers,
            command_rx,
            subscriptions: Default::default(),
            metrics,
            queue: TxQueue::new(config.max_queued_per_eoa),
            config,
            tasks: JoinSet::new(),
            storage: storage.clone(),
        };

        // create all the signers
        for signer in signers {
            this.create_signer(signer, provider.clone(), monitor.clone()).await?;
        }

        // insert loaded queue, we need to do it after signers are created so that loaded pending
        // transactions are inserted first
        for tx in this.storage.read_queued_transactions(chain_id).await? {
            this.push_to_queue(tx);
        }

        let handle = TransactionServiceHandle { command_tx, storage };

        Ok((this, handle))
    }

    /// Creates a new [`Signer`] instance and spawns it.
    async fn create_signer(
        &mut self,
        signer: DynSigner,
        provider: DynProvider,
        monitor: TransactionMonitoringHandle,
    ) -> eyre::Result<()> {
        let signer_id = self.next_signer_id();
        debug!(%signer_id, "creating new signer");
        let metrics = self.metrics.clone();
        let events_tx = self.to_service.clone();
        let signer = Signer::new(
            signer_id,
            provider,
            signer,
            self.storage.clone(),
            events_tx,
            metrics,
            self.config.clone(),
            monitor,
        )
        .await?;
        let (task, loaded_transactions) = signer.into_future().await?;

        // track new signer
        self.insert_active_signer(signer_id, task);

        // insert loaded transactions
        for tx in loaded_transactions {
            self.queue.on_sent_transaction(&tx.tx);
        }

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
                "signer is still paused {signer_id:?}; duplicate entry"
            );
            debug_assert!(
                !self.is_active_signer(&signer_id),
                "signer is already active {signer_id:?}"
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
                "signer is still active {signer_id:?}; duplicate entry"
            );
            debug_assert!(
                !self.is_paused_signer(&signer_id),
                "signer is already paused {signer_id:?}"
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
    fn best_signer_and_tx(&mut self) -> Option<(&mut SignerTask, RelayTransaction)> {
        // Shuffle the signers to make sure transactions are distributed evenly.
        let mut signers = self.signers.iter_mut().collect::<Vec<_>>();
        signers.shuffle(&mut rand::rng());

        let mut best_signer = None;
        let mut best_capacity = 0;
        let mut total_pending = 0;

        for signer in signers {
            total_pending += signer.pending();

            let capacity = signer.capacity();
            if capacity > best_capacity {
                best_signer = Some(signer);
                best_capacity = capacity;
            }
        }

        best_signer
            .filter(|_| total_pending < self.config.max_pending_transactions)
            .and_then(|signer| Some((signer, self.queue.pop_ready()?)))
    }

    /// Sends the given transaction to an available signer.
    fn send_transaction(
        &mut self,
        tx: RelayTransaction,
        status_tx: mpsc::UnboundedSender<TransactionStatus>,
    ) {
        debug_assert!(
            !self.subscriptions.contains_key(&tx.id),
            "tx subscription already exists {}",
            tx.id
        );

        self.subscriptions.insert(tx.id, status_tx);
        self.push_to_queue(tx);
    }

    /// Pushes a transaction to the queue.
    fn push_to_queue(&mut self, tx: RelayTransaction) {
        let tx_id = tx.id;
        if let Err(err) = self.queue.push_transaction(tx) {
            let status = TransactionStatus::Failed(Arc::new(err));

            // If we've failed to record transaction in internal queue, we need to remove it from
            // database.
            let storage = self.storage.clone();
            let to_service = self.to_service.clone();
            self.tasks.spawn(async move {
                storage.remove_queued(tx_id).await?;
                storage.write_transaction_status(tx_id, &status).await?;
                let _ = to_service.send(SignerEvent::TransactionStatus(tx_id, status));

                Ok(())
            });
        } else {
            self.metrics.queued.increment(1);
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

        // drain messages from signers
        while let Poll::Ready(Some(event)) = this.from_signers.poll_recv(cx) {
            match event {
                SignerEvent::TransactionStatus(id, status) => {
                    match &status {
                        TransactionStatus::Failed(err) => {
                            debug!(tx_id = %id, %err, "transaction failed");
                            this.metrics.failed.increment(1);
                        }
                        TransactionStatus::Confirmed(receipt) => {
                            debug!(tx_id = %id, %receipt.transaction_hash, "transaction confirmed");
                            this.metrics.confirmed.increment(1);
                        }
                        _ => {}
                    }

                    if let Some(status_tx) = this.subscriptions.get(&id) {
                        let _ = status_tx.send(status.clone());
                    }

                    if status.is_final() {
                        this.subscriptions.remove(&id);
                        this.queue.on_finished_pending(&id);
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

        // Try advancing the queue.
        while this.queue.has_ready() {
            let Some((signer, tx)) = this.best_signer_and_tx() else { break };
            signer.push_transaction(tx);

            this.metrics.sent.increment(1);
            this.metrics.queued.decrement(1);
        }

        while let Poll::Ready(Some(result)) = this.tasks.poll_join_next(cx) {
            if !matches!(result, Ok(Ok(_))) {
                error!("tx service task failed: {:?}", result);
            }
        }

        this.metrics.poll_duration.record(instant.elapsed().as_nanos() as f64);

        Poll::Pending
    }
}

/// Pool of transactions managed by the service.
///
/// Invariants:
/// - EOA can have at most one pending or ready transaction.
/// - If EOA has any blocked transactions, it must have either one pending or one ready transaction.
///
/// Transaction lifecycle:
/// - [`TxQueue::push_transaction`] must be called for every queued transaction.
/// - [`TxQueue::on_sent_transaction`] must be called when a transaction is sent.
/// - [`TxQueue::pop_ready`] yields a transaction that is ready to be sent, and invokes
///   [`TxQueue::on_sent_transaction`] with it.
/// - [`TxQueue::on_finished_pending`] must be called when a transaction has confirmed or failed.
#[derive(Debug, Default)]
struct TxQueue {
    /// Mapping of an EOA to a currently pending transaction for it.
    eoa_to_pending: HashMap<Address, HashSet<TxId>>,
    /// Mapping of a pending transaction to EOA that it belongs to.
    pending_to_eoa: HashMap<TxId, Address>,

    /// Queue of transactions that are ready to be sent.
    ready: VecDeque<RelayTransaction>,
    /// Number of transactions in ready queue per EOA.
    ready_per_eoa: HashMap<Address, usize>,

    /// Mapping from EOA to a queue of currently blocked transactions that are waiting for another
    /// transaction from this EOA to confirm.
    blocked: HashMap<Address, VecDeque<RelayTransaction>>,

    /// Max number of queued transactions per EOA.
    max_queued_per_eoa: usize,
}

impl TxQueue {
    /// Creates a new [`TxQueue`].
    fn new(max_queued_per_eoa: usize) -> Self {
        Self { max_queued_per_eoa, ..Default::default() }
    }

    /// Returns the number of transactions queued for the given EOA.
    fn count_queued(&self, eoa: &Address) -> usize {
        self.ready_per_eoa.get(eoa).copied().unwrap_or_default()
            + self.blocked.get(eoa).map(|v| v.len()).unwrap_or_default()
    }

    /// Pushes a transaction to the queue. Returns false on error.
    fn push_transaction(&mut self, tx: RelayTransaction) -> Result<(), QueueError> {
        let Some(eoa) = tx.eoa() else {
            // fast path: internal transactions are never blocked
            self.ready.push_back(tx);
            return Ok(());
        };

        if self.count_queued(eoa) >= self.max_queued_per_eoa {
            return Err(QueueError::CapacityOverflow);
        }

        // if we have a pending transaction for this eoa, next transaction is blocked.
        if self.eoa_to_pending.get(eoa).is_some_and(|p| !p.is_empty()) {
            self.blocked.entry(*eoa).or_default().push_back(tx);
        } else if self.ready_per_eoa.get(eoa).copied().unwrap_or_default() == 0 {
            // if there are no pending or ready transactions, push to ready queue
            *self.ready_per_eoa.entry(*eoa).or_default() += 1;
            self.ready.push_back(tx);
        } else {
            // otherwise, push to blocked queue
            self.blocked.entry(*eoa).or_default().push_back(tx);
        }

        Ok(())
    }

    /// Returns whether there are any transactions ready to be sent.
    fn has_ready(&self) -> bool {
        !self.ready.is_empty()
    }

    /// Invoked when a pending transaction is sent.
    fn on_sent_transaction(&mut self, tx: &RelayTransaction) {
        let Some(eoa) = tx.eoa() else { return };
        self.eoa_to_pending.entry(*eoa).or_default().insert(tx.id);
        self.pending_to_eoa.insert(tx.id, *eoa);
    }

    /// Returns the next transaction from the ready queue. Assumes that it will be sent immediately
    /// and accounts for it.
    fn pop_ready(&mut self) -> Option<RelayTransaction> {
        self.ready.pop_front().inspect(|tx| {
            if let Some(eoa) = tx.eoa() {
                if let Some(ready) = self.ready_per_eoa.get_mut(eoa) {
                    *ready -= 1;
                    if *ready == 0 {
                        self.ready_per_eoa.remove(eoa);
                    }
                }
            }

            self.on_sent_transaction(tx)
        })
    }

    /// Handles a finished pending transaction, promotes next blocked transaction for the EOA to
    /// ready queue.
    fn on_finished_pending(&mut self, tx_id: &TxId) {
        // remove transaction from pending set
        let Some(eoa) = self.pending_to_eoa.remove(tx_id) else { return };
        if let Some(pending) = self.eoa_to_pending.get_mut(&eoa) {
            pending.remove(tx_id);
        }

        // promote blocked, if any
        let Some(blocked) = self.blocked.get_mut(&eoa) else { return };
        if let Some(tx) = blocked.pop_front() {
            *self.ready_per_eoa.entry(eoa).or_default() += 1;
            self.ready.push_back(tx);
        };
        if blocked.is_empty() {
            self.blocked.remove(&eoa);
        }
    }
}

/// Errors that can occur while processing transactions by queue.
#[derive(Debug, thiserror::Error)]
enum QueueError {
    /// Returned when we don't have enough capacity to push the transaction.
    #[error("transaction is over queue capacity")]
    CapacityOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Intent, Quote};
    use alloy::{eips::eip1559::Eip1559Estimation, primitives::U256};

    fn create_tx(sender: Address) -> RelayTransaction {
        let quote = Quote {
            chain_id: Default::default(),
            extra_payment: Default::default(),
            payment_token_decimals: Default::default(),
            eth_price: Default::default(),
            tx_gas: Default::default(),
            native_fee_estimate: Eip1559Estimation {
                max_fee_per_gas: Default::default(),
                max_priority_fee_per_gas: Default::default(),
            },
            authorization_address: Default::default(),
            orchestrator: Default::default(),
            intent: Intent { eoa: sender, nonce: U256::random(), ..Default::default() },
            is_multi_chain: false,
        };
        RelayTransaction::new(quote, None)
    }

    #[test]
    fn test_lifecycle() {
        let mut pool = TxQueue::new(100);
        let sender = Address::random();

        let tx = create_tx(sender);
        pool.push_transaction(tx.clone()).unwrap();
        let ready = pool.pop_ready().unwrap();
        assert_eq!(ready.id, tx.id);
        pool.on_finished_pending(&tx.id);

        assert_eq!(pool.count_queued(&sender), 0)
    }

    #[test]
    fn test_limit() {
        let mut pool = TxQueue::new(1);
        let sender = Address::random();

        let tx_0 = create_tx(sender);
        pool.push_transaction(tx_0.clone()).unwrap();

        // assert that we can't push new tx while another one is in queue
        assert!(pool.push_transaction(create_tx(sender)).is_err());

        // pop the queued tx
        let ready = pool.pop_ready().unwrap();
        assert_eq!(ready.id, tx_0.id);
        assert_eq!(pool.count_queued(&sender), 0);

        // assert that we can push now when another tx is pending
        let tx_1 = create_tx(sender);
        pool.push_transaction(tx_1.clone()).unwrap();
        pool.on_finished_pending(&tx_0.id);
        assert_eq!(pool.count_queued(&sender), 1);

        let ready = pool.pop_ready().unwrap();
        assert_eq!(ready.id, tx_1.id);
        assert_eq!(pool.count_queued(&sender), 0);
    }
}
