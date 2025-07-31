use super::{LayerZeroBatchMessage, LayerZeroPoolHandle, pool::LayerZeroBatchPool};
use crate::{
    interop::settler::{
        SettlementError,
        layerzero::{EndpointId, contracts::ILayerZeroEndpointV2},
    },
    storage::{RelayStorage, StorageApi},
    transactions::{RelayTransaction, TransactionServiceHandle, TransactionStatus, TxId},
    types::{
        Call3, LZChainConfigs, LayerZeroNonceRecord, TransactionServiceHandles, aggregate3Call,
    },
};
use alloy::{
    primitives::{B256, ChainId, map::HashMap},
    providers::{MULTICALL3_ADDRESS, Provider},
    rpc::types::TransactionRequest,
    sol_types::SolCall,
};
use std::time::Duration;
use tokio::{sync::mpsc, time::interval};
use tracing::{error, info};

/// Processor monitoring and executing LayerZero settlement batches.
#[derive(Debug, Clone)]
pub struct LayerZeroBatchProcessor {
    /// Storage for persistence
    storage: RelayStorage,
    /// Chain configurations
    chain_configs: LZChainConfigs,
    /// Handle to communicate with batch pool
    pool_handle: LayerZeroPoolHandle,
}

impl LayerZeroBatchProcessor {
    /// Run batch processor with its associated pool, returning pool handle.
    pub async fn run(
        storage: RelayStorage,
        chain_configs: LZChainConfigs,
        tx_service_handles: TransactionServiceHandles,
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
        tx_service_handles: TransactionServiceHandles,
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
            .update_lz_nonce_and_queue_transaction(chain_id, src_eid, last_nonce, &batch_tx)
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

                // Update highest nonce (also removes processed entries)
                self.pool_handle
                    .update_highest_nonce(chain_id, src_eid, highest_nonce, tx_id)
                    .await;

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
