//! Batch processing for LayerZero settlements.
//!
//! Components:
//! - **LayerZeroBatchPool**: Manages pending settlements by (chain_id, src_eid)
//! - **LayerZeroBatchProcessor**: Processes batches sequentially with nonce ordering
//!
//! Features: Sequential processing, crash recovery, parallel chain processing.

use super::{EndpointId, LZChainConfig, contracts::ILayerZeroEndpointV2};
use crate::{
    interop::settler::SettlementError,
    storage::{RelayStorage, StorageApi},
    transactions::{RelayTransaction, TransactionServiceHandle, TransactionStatus, TxId},
    types::{Call3, LayerZeroNonceRecord, aggregate3Call},
};
use alloy::{
    primitives::{B256, ChainId, map::HashMap},
    providers::{MULTICALL3_ADDRESS, Provider},
    rpc::types::TransactionRequest,
    sol_types::SolCall,
};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::{
    sync::{mpsc, oneshot},
    time::interval,
};
use tracing::{error, info};

/// LayerZero settlement message to be batched.
#[derive(Debug, Clone)]
pub struct LayerZeroBatchMessage {
    /// Destination chain ID
    pub chain_id: ChainId,
    /// Source LayerZero endpoint ID  
    pub src_eid: EndpointId,
    /// LayerZero nonce for this message
    pub nonce: u64,
    /// The calls to execute
    pub calls: Vec<Call3>,
}

/// Pending batch of LayerZero messages.
#[derive(Debug, Clone, Default)]
pub struct PendingBatch {
    /// Settlements that can be processed in this batch (gapless from current nonce)
    pub settlements: Vec<LayerZeroBatchMessage>,
    /// Total number of settlements available in the pool for this chain pair, including these
    /// ones.
    pub total_pool_available: usize,
}

impl PendingBatch {
    /// Create a new pending batch
    pub fn new(settlements: Vec<LayerZeroBatchMessage>, total_available: usize) -> Self {
        Self { settlements, total_pool_available: total_available }
    }

    /// Check if the batch is empty
    pub fn is_empty(&self) -> bool {
        self.settlements.is_empty()
    }

    /// Get the number of messages in this batch
    pub fn len(&self) -> usize {
        self.settlements.len()
    }
}

/// Messages for communicating with the LayerZeroBatchPool.
#[derive(Debug)]
pub enum LayerZeroPoolMessages {
    /// New settlement to process
    Settlement(LayerZeroBatchMessage, oneshot::Sender<Result<(), SettlementError>>),
    /// Get pending gapless batch starting from highest_nonce + 1
    GetPendingBatch {
        /// Chain ID to get batch for
        chain_id: ChainId,
        /// Source endpoint ID
        src_eid: EndpointId,
        /// Current highest nonce confirmed
        highest_nonce: u64,
        /// Channel to send response
        response: oneshot::Sender<PendingBatch>,
    },
    /// Update highest nonce confirmed
    UpdateHighestNonce(ChainId, EndpointId, u64, TxId),
    /// Remove processed settlements up to and including highest_nonce
    RemoveProcessed {
        /// Chain ID
        chain_id: ChainId,
        /// Source endpoint ID
        src_eid: EndpointId,
        /// Highest nonce to remove up to
        highest_nonce: u64,
    },
    /// Get highest nonce for a specific chain/eid
    GetHighestNonce {
        /// Chain ID
        chain_id: ChainId,
        /// Source endpoint ID
        src_eid: EndpointId,
        /// Channel to send response
        response: oneshot::Sender<Option<u64>>,
    },
}

/// Pool maintaining pending LayerZero settlements organized by (chain_id, src_eid).
#[derive(Debug)]
struct LayerZeroBatchPool {
    /// Receiver for service messages
    receiver: mpsc::UnboundedReceiver<LayerZeroPoolMessages>,
    /// Pending settlements grouped by (chain_id, src_eid)
    pending_settlements: HashMap<(ChainId, EndpointId), BTreeMap<u64, PendingSettlementEntry>>,
    /// Highest nonce confirmed per (chain_id, src_eid) with tx_id
    highest_nonce_confirmed: HashMap<(ChainId, EndpointId), (u64, TxId)>,
}

/// Handle for interacting with the LayerZeroBatchPool.
#[derive(Debug, Clone)]
pub struct LayerZeroPoolHandle {
    sender: mpsc::UnboundedSender<LayerZeroPoolMessages>,
}

/// Type alias for pending settlement entry
type PendingSettlementEntry = (LayerZeroBatchMessage, oneshot::Sender<Result<(), SettlementError>>);

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
        calls: Vec<Call3>,
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

    /// Update the highest nonce confirmed for a chain
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

    /// Remove processed settlements up to and including highest_nonce
    pub async fn remove_processed(
        &self,
        chain_id: ChainId,
        src_eid: EndpointId,
        highest_nonce: u64,
    ) {
        let _ = self.sender.send(LayerZeroPoolMessages::RemoveProcessed {
            chain_id,
            src_eid,
            highest_nonce,
        });
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

impl LayerZeroBatchPool {
    /// Create a new batch pool
    pub fn new(receiver: mpsc::UnboundedReceiver<LayerZeroPoolMessages>) -> Self {
        Self {
            receiver,
            pending_settlements: HashMap::default(),
            highest_nonce_confirmed: HashMap::default(),
        }
    }

    /// Spawn the batch pool - handles messages
    pub fn spawn(mut self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            while let Some(message) = self.receiver.recv().await {
                match message {
                    LayerZeroPoolMessages::Settlement(msg, sender) => {
                        let key = (msg.chain_id, msg.src_eid);

                        // Check if nonce is already confirmed
                        if let Some(&(highest_nonce, _)) = self.highest_nonce_confirmed.get(&key)
                            && msg.nonce <= highest_nonce
                        {
                            let _ = sender.send(Ok(()));
                            continue;
                        }

                        // Add to pending settlements
                        self.pending_settlements
                            .entry(key)
                            .or_default()
                            .insert(msg.nonce, (msg, sender));
                    }
                    LayerZeroPoolMessages::GetPendingBatch {
                        chain_id,
                        src_eid,
                        highest_nonce,
                        response,
                    } => {
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
                                        Some((msg, _)) => {
                                            messages.push(msg.clone());
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
                    LayerZeroPoolMessages::UpdateHighestNonce(chain_id, src_eid, nonce, tx_id) => {
                        self.highest_nonce_confirmed.insert((chain_id, src_eid), (nonce, tx_id));

                        info!(
                            chain_id = chain_id,
                            src_eid = src_eid,
                            highest_nonce = nonce,
                            "Batch confirmed on chain"
                        );
                    }
                    LayerZeroPoolMessages::RemoveProcessed { chain_id, src_eid, highest_nonce } => {
                        if let Some(pending) =
                            self.pending_settlements.get_mut(&(chain_id, src_eid))
                        {
                            // Collect nonces to remove and send confirmations
                            let to_remove: Vec<_> =
                                pending.range(..=highest_nonce).map(|(&nonce, _)| nonce).collect();

                            for nonce in to_remove {
                                if let Some((_, sender)) = pending.remove(&nonce) {
                                    let _ = sender.send(Ok(()));
                                }
                            }
                        }
                    }
                    LayerZeroPoolMessages::GetHighestNonce { chain_id, src_eid, response } => {
                        let result = self
                            .highest_nonce_confirmed
                            .get(&(chain_id, src_eid))
                            .map(|(nonce, _)| *nonce);
                        let _ = response.send(result);
                    }
                }
            }
        })
    }
}

/// Processor monitoring and executing LayerZero settlement batches.
#[derive(Debug, Clone)]
pub struct LayerZeroBatchProcessor {
    /// Storage for persistence
    storage: RelayStorage,
    /// Chain configurations
    chain_configs: Arc<HashMap<ChainId, LZChainConfig>>,
    /// Handle to communicate with batch pool
    pool_handle: LayerZeroPoolHandle,
}

impl LayerZeroBatchProcessor {
    /// Run batch processor with its associated pool, returning pool handle.
    pub async fn run(
        storage: RelayStorage,
        chain_configs: Arc<HashMap<ChainId, LZChainConfig>>,
        tx_service_handles: Arc<HashMap<ChainId, TransactionServiceHandle>>,
    ) -> Result<LayerZeroPoolHandle, SettlementError> {
        // Create channels for pool and processor communication
        let (msg_sender, msg_receiver) = mpsc::unbounded_channel();

        // Spawn the pool
        LayerZeroBatchPool::new(msg_receiver).spawn();

        // Create pool handle
        let pool_handle = LayerZeroPoolHandle::new(msg_sender);

        // Spawn the processor
        Self { storage, chain_configs, pool_handle: pool_handle.clone() }
            .spawn(tx_service_handles)
            .await?;

        Ok(pool_handle)
    }

    /// Spawn dedicated tasks for each (destination_chain, source_endpoint) pair.
    async fn spawn(
        self,
        tx_service_handles: Arc<HashMap<ChainId, TransactionServiceHandle>>,
    ) -> Result<(), SettlementError> {
        // Create a map of the latest handled nonces by (chain_id, src_eid)
        let nonce_map: HashMap<(ChainId, EndpointId), LayerZeroNonceRecord> = self
            .storage
            .get_latest_layerzero_nonces()
            .await?
            .into_iter()
            .map(|record| ((record.chain_id, record.src_eid as EndpointId), record))
            .collect();

        // Build all possible (chain_id, src_eid) combinations from chain configs
        let mut chains_to_process = Vec::new();
        for (dst_chain_id, _) in self.chain_configs.iter() {
            // For each destination chain, we can receive from any other chain
            for (src_chain_id, src_config) in self.chain_configs.iter() {
                if src_chain_id != dst_chain_id {
                    // We process settlements on dst_chain_id that came from src_eid
                    chains_to_process.push((*dst_chain_id, src_config.endpoint_id));
                }
            }
        }

        // Spawn a dedicated task for each chain pair
        for (chain_id, src_eid) in chains_to_process {
            // Get the transaction service handle for this specific chain
            let tx_service_handle = match tx_service_handles.get(&chain_id) {
                Some(handle) => handle.clone(),
                None => {
                    error!("No transaction service handle for chain {}, skipping", chain_id);
                    continue;
                }
            };

            // Get the nonce record for this chain pair, if any
            let nonce_record = nonce_map.get(&(chain_id, src_eid)).cloned();

            let processor = self.clone();
            tokio::spawn(async move {
                processor
                    .process_chain_pair(tx_service_handle, chain_id, src_eid, nonce_record)
                    .await;
            });
        }

        Ok(())
    }

    /// Process batches for a specific chain pair.
    async fn process_chain_pair(
        &self,
        tx_service_handle: TransactionServiceHandle,
        chain_id: ChainId,
        src_eid: EndpointId,
        record: Option<LayerZeroNonceRecord>,
    ) {
        let mut interval = interval(Duration::from_millis(200)); // ~1 block time

        info!(chain_id = chain_id, src_eid = src_eid, "Starting batch processor for chain pair");
        if let Some(record) = record {
            // We have a nonce record from storage - need to wait for it to confirm
            info!(
                chain_id = chain_id,
                src_eid = src_eid,
                tx_id = %record.tx_id,
                nonce = record.nonce_lz,
                "Found existing transaction, waiting for confirmation"
            );

            if let Err(e) = self
                .wait_for_transaction(
                    &tx_service_handle,
                    record.tx_id,
                    chain_id,
                    src_eid,
                    record.nonce_lz,
                )
                .await
            {
                error!(
                    chain_id = chain_id,
                    src_eid = src_eid,
                    error = ?e,
                    "Failed to wait for existing transaction"
                );
            }
        }

        loop {
            // Process next batch for this chain pair
            if let Err(e) = self.process_next_batch(&tx_service_handle, chain_id, src_eid).await {
                error!(
                    chain_id = chain_id,
                    src_eid = src_eid,
                    error = ?e,
                    "Failed to process batch for chain pair"
                );
            }

            interval.tick().await;
        }
    }

    /// Process the next batch for a specific chain pair.
    ///
    /// This method:
    /// 1. Checks if the previous transaction is complete
    /// 2. Retrieves the next gapless batch from the pool
    /// 3. Creates a multicall transaction for the batch
    /// 4. Queues the transaction in storage
    /// 5. Sends it via TransactionService
    /// 6. Waits for confirmation and updates pool state
    async fn process_next_batch(
        &self,
        tx_service_handle: &TransactionServiceHandle,
        chain_id: ChainId,
        src_eid: EndpointId,
    ) -> Result<(), SettlementError> {
        // Get the highest nonce for this chain/eid
        let current_nonce =
            if let Some(nonce) = self.pool_handle.get_highest_nonce(chain_id, src_eid).await {
                nonce
            } else {
                // No batches sent yet, get from chain
                self.get_current_inbound_nonce(chain_id, src_eid).await?
            };

        // Get the gapless batch starting from current_nonce
        let mut pending_batch =
            self.pool_handle.get_pending_batch(chain_id, src_eid, current_nonce).await;

        // If batch is empty but we have pending messages, check if we have a nonce mismatch
        if pending_batch.is_empty() && pending_batch.total_pool_available > 1 {
            info!(
                chain_id = chain_id,
                src_eid = src_eid,
                total_available = pending_batch.total_pool_available,
                current_nonce = current_nonce,
                "No gapless batch found but many pending messages, checking chain nonce"
            );

            let chain_nonce = self.get_current_inbound_nonce(chain_id, src_eid).await?;
            if chain_nonce != current_nonce {
                info!(
                    chain_id = chain_id,
                    src_eid = src_eid,
                    pool_nonce = current_nonce,
                    chain_nonce = chain_nonce,
                    "Nonce mismatch detected, retrying with chain nonce"
                );

                // Try again with the chain nonce
                pending_batch =
                    self.pool_handle.get_pending_batch(chain_id, src_eid, chain_nonce).await;
            }
        }

        if pending_batch.is_empty() {
            return Ok(());
        }

        info!(
            chain_id = chain_id,
            src_eid = src_eid,
            batch_size = pending_batch.len(),
            total_available = pending_batch.total_pool_available,
            start_nonce = pending_batch.settlements.first().unwrap().nonce,
            "Building LayerZero batch"
        );

        // Create and queue batch transaction
        let batch_tx = self.create_batch_transaction(chain_id, &pending_batch.settlements).await?;
        let tx_id = batch_tx.id;

        // Update LayerZero nonce and queue transaction atomically
        let last_nonce = pending_batch.settlements.last().unwrap().nonce;
        self.storage
            .update_lz_nonce_and_queue_transaction(chain_id, src_eid, last_nonce, tx_id, &batch_tx)
            .await
            .map_err(|e| SettlementError::InternalError(format!("Storage error: {e:?}")))?;

        // Send transaction and don't wait for the status updates
        let _ = tx_service_handle.send_transaction_no_queue(batch_tx);

        // Wait for transaction to complete
        self.wait_for_transaction(tx_service_handle, tx_id, chain_id, src_eid, last_nonce).await
    }

    /// Wait for transaction confirmation and update pool state.
    async fn wait_for_transaction(
        &self,
        tx_service_handle: &TransactionServiceHandle,
        tx_id: TxId,
        chain_id: ChainId,
        src_eid: EndpointId,
        highest_nonce: u64,
    ) -> Result<(), SettlementError> {
        info!(
            chain_id = chain_id,
            src_eid = src_eid,
            tx_id = %tx_id,
            "Waiting for transaction to be confirmed"
        );

        let status = tx_service_handle.wait_for_tx(tx_id).await.map_err(|e| {
            error!(
                chain_id = chain_id,
                src_eid = src_eid,
                tx_id = %tx_id,
                error = ?e,
                "Failed to wait for transaction"
            );
            SettlementError::InternalError(format!("Failed to wait for transaction: {e:?}"))
        })?;

        match status {
            TransactionStatus::Confirmed(_) => {
                info!(
                    chain_id = chain_id,
                    src_eid = src_eid,
                    tx_id = %tx_id,
                    highest_nonce = highest_nonce,
                    "Transaction confirmed, updating highest nonce"
                );

                // Update highest nonce
                self.pool_handle
                    .update_highest_nonce(chain_id, src_eid, highest_nonce, tx_id)
                    .await;

                // Remove processed settlements up to highest_nonce
                self.pool_handle.remove_processed(chain_id, src_eid, highest_nonce).await;

                Ok(())
            }
            TransactionStatus::Failed(reason) => {
                error!(
                    chain_id = chain_id,
                    src_eid = src_eid,
                    tx_id = %tx_id,
                    reason = ?reason,
                    "Transaction failed"
                );
                Err(SettlementError::InternalError(format!("Transaction failed: {reason:?}")))
            }
            status => {
                error!(
                    chain_id = chain_id,
                    src_eid = src_eid,
                    tx_id = %tx_id,
                    status = ?status,
                    "Unexpected transaction status"
                );
                Err(SettlementError::InternalError(format!(
                    "Unexpected transaction status: {status:?}"
                )))
            }
        }
    }

    /// Create multicall transaction for batch.
    async fn create_batch_transaction(
        &self,
        chain_id: ChainId,
        batch: &[LayerZeroBatchMessage],
    ) -> Result<RelayTransaction, SettlementError> {
        let config = self
            .chain_configs
            .get(&chain_id)
            .ok_or_else(|| SettlementError::UnsupportedChain(chain_id))?;

        // Build multicall with all batch operations
        let all_calls: Vec<Call3> =
            batch.iter().flat_map(|message| message.calls.clone()).collect();

        let multicall_calldata = aggregate3Call { calls: all_calls }.abi_encode();

        // Estimate gas for the batch
        let tx_request = TransactionRequest::default()
            .to(MULTICALL3_ADDRESS)
            .input(multicall_calldata.clone().into());

        let gas_limit =
            config.provider.estimate_gas(tx_request).await.map_err(SettlementError::RpcError)?;

        // Add buffer for batch processing
        let gas_limit = gas_limit.saturating_mul(130).saturating_div(100);

        Ok(RelayTransaction::new_internal(
            MULTICALL3_ADDRESS,
            multicall_calldata,
            chain_id,
            gas_limit,
        ))
    }

    /// Get current inbound nonce from LayerZero endpoint.
    async fn get_current_inbound_nonce(
        &self,
        chain_id: ChainId,
        src_eid: EndpointId,
    ) -> Result<u64, SettlementError> {
        let config = self
            .chain_configs
            .get(&chain_id)
            .ok_or_else(|| SettlementError::UnsupportedChain(chain_id))?;

        // Query the endpoint for the current inbound nonce
        let endpoint = ILayerZeroEndpointV2::new(config.endpoint_address, &config.provider);

        // Get the inbound nonce for the source endpoint
        let src_config = self
            .chain_configs
            .iter()
            .find(|(_, c)| c.endpoint_id == src_eid)
            .map(|(_, c)| c)
            .ok_or_else(|| SettlementError::UnknownEndpointId(src_eid))?;

        let sender = B256::left_padding_from(src_config.settler_address.as_slice());

        let nonce = endpoint
            .inboundNonce(config.settler_address, src_eid, sender)
            .call()
            .await
            .map_err(|e| SettlementError::InternalError(e.to_string()))?;

        Ok(nonce)
    }
}
