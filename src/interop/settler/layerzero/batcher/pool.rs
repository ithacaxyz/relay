use super::{
    LayerZeroBatchMessage, LayerZeroPoolMessages, MAX_SETTLEMENTS_PER_BATCH, PendingBatch,
    processor::LayerZeroBatchProcessor,
    types::{PendingSettlementEntry, SettlementPathKey},
};
use crate::{
    interop::settler::{SettlementError, layerzero::EndpointId},
    transactions::TxId,
    types::{LZChainConfigs, TransactionServiceHandles},
};
use alloy::primitives::{Address, ChainId, map::HashMap};
use std::collections::BTreeMap;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{debug, info};

/// Handle for interacting with the LayerZeroBatchPool.
#[derive(Debug, Clone)]
pub struct LayerZeroPoolHandle {
    sender: mpsc::UnboundedSender<LayerZeroPoolMessages>,
}

impl LayerZeroPoolHandle {
    /// Create a new pool handle
    pub fn new(sender: mpsc::UnboundedSender<LayerZeroPoolMessages>) -> Self {
        Self { sender }
    }

    /// Submit settlement to pool and wait for confirmation.
    pub async fn send_settlement_and_wait(
        &self,
        chain_id: ChainId,
        src_eid: EndpointId,
        nonce: u64,
        calls: Vec<crate::types::Call3>,
        settler_address: Address,
    ) -> Result<(), SettlementError> {
        // Create oneshot channel for direct notification
        let (tx, rx) = oneshot::channel();

        // Create the message without the response sender
        let settlement = LayerZeroBatchMessage { chain_id, src_eid, nonce, calls, settler_address };

        // Send the message with the sender separately
        debug!(?chain_id, ?nonce, ?settler_address, "Sending settlement for processing.");
        let _ = self.sender.send(LayerZeroPoolMessages::Settlement { settlement, response: tx });
        rx.await.map_err(|_| SettlementError::InternalError("Channel closed".to_string()))?
    }

    /// Get pending batch for a chain starting from highest_nonce + 1.
    pub async fn get_pending_batch(
        &self,
        key: SettlementPathKey,
        highest_nonce: u64,
    ) -> PendingBatch {
        let (tx, rx) = oneshot::channel();
        let _ = self.sender.send(LayerZeroPoolMessages::GetPendingBatch {
            key,
            highest_nonce,
            response: tx,
        });
        rx.await.unwrap_or_else(|_| PendingBatch::default())
    }

    /// Update the highest nonce confirmed for a chain and remove processed settlements
    pub async fn update_highest_nonce(&self, key: SettlementPathKey, nonce: u64, tx_id: TxId) {
        let _ = self.sender.send(LayerZeroPoolMessages::UpdateHighestNonce { key, nonce, tx_id });
    }

    /// Get highest nonce for a specific chain/eid
    pub async fn get_highest_nonce(&self, key: SettlementPathKey) -> Option<u64> {
        let (tx, rx) = oneshot::channel();
        let _ = self.sender.send(LayerZeroPoolMessages::GetHighestNonce { key, response: tx });
        rx.await.unwrap_or(None)
    }

    /// Subscribe to pool size updates for a specific chain/eid
    pub async fn subscribe(&self, key: SettlementPathKey) -> Option<watch::Receiver<usize>> {
        let (tx, rx) = oneshot::channel();
        self.sender.send(LayerZeroPoolMessages::Subscribe { key, response: tx }).ok()?;
        rx.await.ok()
    }
}

/// Pool maintaining pending LayerZero settlements organized by SettlementPathKey.
#[derive(Debug)]
pub struct LayerZeroBatchPool {
    /// Receiver for service messages
    receiver: mpsc::UnboundedReceiver<LayerZeroPoolMessages>,
    /// Pending settlements grouped by settlement path key
    pending_settlements: HashMap<SettlementPathKey, BTreeMap<u64, PendingSettlementEntry>>,
    /// Highest nonce confirmed per settlement path key with tx_id
    highest_nonce_confirmed: HashMap<SettlementPathKey, (u64, TxId)>,
    /// Watch channels for pool size updates per settlement path key
    pool_watchers: HashMap<SettlementPathKey, watch::Sender<usize>>,
    /// Processor for spawning settlement path handlers
    processor: LayerZeroBatchProcessor,
}

impl LayerZeroBatchPool {
    /// Set up the LayerZero batching system by creating a pool and returning its handle.
    ///
    /// This method:
    /// 1. Creates a pool that manages pending settlements organized by [`SettlementPathKey`]
    /// 2. Creates a processor that can spawn batchers for different settlement paths
    /// 3. Returns a handle for submitting settlements
    ///
    /// When settlements arrive:
    /// - Pool checks if this is a new settler address it hasn't seen before
    /// - If new, pool asks processor to spawn a dedicated batcher for that settlement path
    /// - Batcher monitors its assigned path and batches settlements
    pub fn setup(
        chain_configs: LZChainConfigs,
        tx_service_handles: TransactionServiceHandles,
    ) -> Result<LayerZeroPoolHandle, SettlementError> {
        // Create channels for pool and processor communication
        let (msg_sender, msg_receiver) = mpsc::unbounded_channel();

        let pool_handle = LayerZeroPoolHandle::new(msg_sender);
        let processor =
            LayerZeroBatchProcessor::new(chain_configs, pool_handle.clone(), tx_service_handles);

        // Create and spawn the pool
        Self {
            receiver: msg_receiver,
            pending_settlements: HashMap::default(),
            highest_nonce_confirmed: HashMap::default(),
            pool_watchers: HashMap::default(),
            processor,
        }
        .spawn();

        Ok(pool_handle)
    }

    /// Notify pool watchers of the current pool size
    fn notify_pool_watchers(&self, key: &SettlementPathKey, size: usize) {
        if let Some(watcher) = self.pool_watchers.get(key) {
            let _ = watcher.send(size);
        }
    }

    /// Handle settlement message
    fn handle_settlement(
        &mut self,
        msg: LayerZeroBatchMessage,
        sender: oneshot::Sender<Result<(), SettlementError>>,
    ) {
        let key = msg.path_key();

        // Check if nonce is already confirmed
        if let Some(&(highest_nonce, _)) = self.highest_nonce_confirmed.get(&key)
            && msg.nonce <= highest_nonce
        {
            let _ = sender.send(Ok(()));
            return;
        }

        // Check if this is a new SettlementPathKey and spawn processor if needed.
        //
        // Note: No race condition here - pool processes messages sequentially,
        // so any Subscribe message from the spawned processor will be handled
        // after this method completes and the entry exists
        if !self.pending_settlements.contains_key(&key) {
            self.processor.spawn_for_settlement_path(key);
        }

        // Add to pending settlements
        let entry = PendingSettlementEntry::new(msg, sender);
        let pending = self.pending_settlements.entry(key).or_default();
        pending.insert(entry.message.nonce, entry);

        let size = pending.len();
        self.notify_pool_watchers(&key, size);
    }

    /// Handle get pending batch message
    fn handle_get_pending_batch(
        &self,
        key: SettlementPathKey,
        highest_nonce: u64,
        response: oneshot::Sender<PendingBatch>,
    ) {
        let pending_batch = self
            .pending_settlements
            .get(&key)
            .map(|pending| {
                let total = pending.len();
                let mut messages = Vec::with_capacity(MAX_SETTLEMENTS_PER_BATCH.min(total));
                let mut current_nonce = highest_nonce + 1;

                for _ in 0..MAX_SETTLEMENTS_PER_BATCH {
                    let Some(entry) = pending.get(&current_nonce) else {
                        break;
                    };
                    messages.push(entry.message.clone());
                    current_nonce += 1;
                }
                PendingBatch::new(messages, total)
            })
            .unwrap_or_default();
        let _ = response.send(pending_batch);
    }

    /// Handle update highest nonce message - also removes processed entries and notifies callers
    fn handle_update_highest_nonce(&mut self, key: SettlementPathKey, nonce: u64, tx_id: TxId) {
        self.highest_nonce_confirmed.insert(key, (nonce, tx_id));

        info!(
            chain_id = key.chain_id,
            src_eid = key.src_eid,
            settler_address = ?key.settler_address,
            highest_nonce = nonce,
            "Batch confirmed on chain"
        );

        // Remove processed settlements and send confirmations
        if let Some(pending) = self.pending_settlements.get_mut(&key) {
            let to_remove: Vec<_> = pending.range(..=nonce).map(|(&n, _)| n).collect();

            for n in to_remove {
                if let Some(entry) = pending.remove(&n) {
                    let _ = entry.response_tx.send(Ok(()));
                }
            }

            let size = pending.len();
            self.notify_pool_watchers(&key, size);
        }
    }

    /// Handle get highest nonce message
    fn handle_get_highest_nonce(
        &self,
        key: SettlementPathKey,
        response: oneshot::Sender<Option<u64>>,
    ) {
        let _ = response.send(self.highest_nonce_confirmed.get(&key).map(|(nonce, _)| *nonce));
    }

    /// Handle subscribe message
    fn handle_subscribe(
        &mut self,
        key: SettlementPathKey,
        response: oneshot::Sender<watch::Receiver<usize>>,
    ) {
        // Get or create watch channel for this pool key
        let watcher = self.pool_watchers.entry(key).or_insert_with(|| {
            let current_size = self.pending_settlements.get(&key).map(|p| p.len()).unwrap_or(0);
            info!(
                chain_id = key.chain_id,
                src_eid = key.src_eid,
                settler_address = ?key.settler_address,
                current_size = current_size,
                "Creating pool watcher for settlement path"
            );
            let (tx, _) = watch::channel(current_size);
            tx
        });

        // Send a receiver to the subscriber
        let _ = response.send(watcher.subscribe());
    }

    /// Spawns the pool that handles messages to add, query or remove settlements.
    pub fn spawn(mut self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            while let Some(message) = self.receiver.recv().await {
                match message {
                    LayerZeroPoolMessages::Settlement { settlement: message, response } => {
                        self.handle_settlement(message, response);
                    }
                    LayerZeroPoolMessages::GetPendingBatch { key, highest_nonce, response } => {
                        self.handle_get_pending_batch(key, highest_nonce, response);
                    }
                    LayerZeroPoolMessages::UpdateHighestNonce { key, nonce, tx_id } => {
                        self.handle_update_highest_nonce(key, nonce, tx_id);
                    }
                    LayerZeroPoolMessages::GetHighestNonce { key, response } => {
                        self.handle_get_highest_nonce(key, response);
                    }
                    LayerZeroPoolMessages::Subscribe { key, response } => {
                        self.handle_subscribe(key, response);
                    }
                }
            }
        })
    }
}
