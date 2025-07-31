use super::{
    LayerZeroBatchMessage, LayerZeroPoolMessages, PendingBatch, types::PendingSettlementEntry,
};
use crate::{
    interop::settler::{SettlementError, layerzero::EndpointId},
    transactions::TxId,
};
use alloy::primitives::{ChainId, map::HashMap};
use std::collections::BTreeMap;
use tokio::sync::{mpsc, oneshot};
use tracing::info;

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

    /// Submit settlement to pool and wait for batch confirmation.
    pub async fn send_settlement_and_wait(
        &self,
        chain_id: ChainId,
        src_eid: EndpointId,
        nonce: u64,
        calls: Vec<crate::types::Call3>,
    ) -> Result<(), SettlementError> {
        // Create oneshot channel for direct notification
        let (tx, rx) = oneshot::channel();

        // Create the message without the response sender
        let batch_message = LayerZeroBatchMessage { chain_id, src_eid, nonce, calls };

        // Send the message with the sender separately
        self.sender
            .send(LayerZeroPoolMessages::Settlement(batch_message, tx))
            .map_err(|_| SettlementError::InternalError("Channel closed".to_string()))?;

        // Wait for direct notification
        rx.await.map_err(|_| SettlementError::InternalError("Channel closed".to_string()))?
    }

    /// Get pending batch for a chain starting from highest_nonce + 1.
    pub async fn get_pending_batch(
        &self,
        chain_id: ChainId,
        src_eid: EndpointId,
        highest_nonce: u64,
    ) -> PendingBatch {
        let (tx, rx) = oneshot::channel();
        let _ = self.sender.send(LayerZeroPoolMessages::GetPendingBatch {
            chain_id,
            src_eid,
            highest_nonce,
            response: tx,
        });
        rx.await.unwrap_or_else(|_| PendingBatch::default())
    }

    /// Update the highest nonce confirmed for a chain and remove processed settlements
    pub async fn update_highest_nonce(
        &self,
        chain_id: ChainId,
        src_eid: EndpointId,
        nonce: u64,
        tx_id: TxId,
    ) {
        let _ = self
            .sender
            .send(LayerZeroPoolMessages::UpdateHighestNonce(chain_id, src_eid, nonce, tx_id));
    }

    /// Get highest nonce for a specific chain/eid
    pub async fn get_highest_nonce(&self, chain_id: ChainId, src_eid: EndpointId) -> Option<u64> {
        let (tx, rx) = oneshot::channel();
        let _ = self.sender.send(LayerZeroPoolMessages::GetHighestNonce {
            chain_id,
            src_eid,
            response: tx,
        });
        rx.await.unwrap_or(None)
    }
}

/// Pool maintaining pending LayerZero settlements organized by (chain_id, src_eid).
#[derive(Debug)]
pub struct LayerZeroBatchPool {
    /// Receiver for service messages
    receiver: mpsc::UnboundedReceiver<LayerZeroPoolMessages>,
    /// Pending settlements grouped by (chain_id, src_eid)
    pending_settlements: HashMap<(ChainId, EndpointId), BTreeMap<u64, PendingSettlementEntry>>,
    /// Highest nonce confirmed per (chain_id, src_eid) with tx_id
    highest_nonce_confirmed: HashMap<(ChainId, EndpointId), (u64, TxId)>,
}

impl LayerZeroBatchPool {
    /// Create a new batch pool
    pub fn new(receiver: mpsc::UnboundedReceiver<LayerZeroPoolMessages>) -> Self {
        Self {
            receiver,
            pending_settlements: HashMap::default(),
            highest_nonce_confirmed: HashMap::default(),
        }
    }

    /// Handle settlement message
    fn handle_settlement(
        &mut self,
        msg: LayerZeroBatchMessage,
        sender: oneshot::Sender<Result<(), SettlementError>>,
    ) {
        let key = (msg.chain_id, msg.src_eid);

        // Check if nonce is already confirmed
        if let Some(&(highest_nonce, _)) = self.highest_nonce_confirmed.get(&key)
            && msg.nonce <= highest_nonce
        {
            let _ = sender.send(Ok(()));
            return;
        }

        // Add to pending settlements
        let entry = PendingSettlementEntry::new(msg, sender);
        self.pending_settlements.entry(key).or_default().insert(entry.message.nonce, entry);
    }

    /// Handle get pending batch message
    fn handle_get_pending_batch(
        &self,
        chain_id: ChainId,
        src_eid: EndpointId,
        highest_nonce: u64,
        response: oneshot::Sender<PendingBatch>,
    ) {
        let key = (chain_id, src_eid);
        let pending_batch = self
            .pending_settlements
            .get(&key)
            .map(|pending| {
                let total = pending.len();
                let mut messages = Vec::with_capacity(20.min(total));
                let mut current_nonce = highest_nonce + 1;

                for _ in 0..20 {
                    match pending.get(&current_nonce) {
                        Some(entry) => {
                            messages.push(entry.message.clone());
                            current_nonce += 1;
                        }
                        None => break,
                    }
                }
                PendingBatch::new(messages, total)
            })
            .unwrap_or_default();
        let _ = response.send(pending_batch);
    }

    /// Handle update highest nonce message - also removes processed entries and notifies callers
    fn handle_update_highest_nonce(
        &mut self,
        chain_id: ChainId,
        src_eid: EndpointId,
        nonce: u64,
        tx_id: TxId,
    ) {
        let key = (chain_id, src_eid);
        self.highest_nonce_confirmed.insert(key, (nonce, tx_id));

        info!(
            chain_id = chain_id,
            src_eid = src_eid,
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
        }
    }

    /// Handle get highest nonce message
    fn handle_get_highest_nonce(
        &self,
        chain_id: ChainId,
        src_eid: EndpointId,
        response: oneshot::Sender<Option<u64>>,
    ) {
        let result =
            self.highest_nonce_confirmed.get(&(chain_id, src_eid)).map(|(nonce, _)| *nonce);
        let _ = response.send(result);
    }

    /// Spawn the batch pool - handles messages
    pub fn spawn(mut self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            while let Some(message) = self.receiver.recv().await {
                match message {
                    LayerZeroPoolMessages::Settlement(msg, sender) => {
                        self.handle_settlement(msg, sender);
                    }
                    LayerZeroPoolMessages::GetPendingBatch {
                        chain_id,
                        src_eid,
                        highest_nonce,
                        response,
                    } => {
                        self.handle_get_pending_batch(chain_id, src_eid, highest_nonce, response);
                    }
                    LayerZeroPoolMessages::UpdateHighestNonce(chain_id, src_eid, nonce, tx_id) => {
                        self.handle_update_highest_nonce(chain_id, src_eid, nonce, tx_id);
                    }
                    LayerZeroPoolMessages::GetHighestNonce { chain_id, src_eid, response } => {
                        self.handle_get_highest_nonce(chain_id, src_eid, response);
                    }
                }
            }
        })
    }
}
