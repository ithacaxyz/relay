use super::{LayerZeroBatchMessage, LayerZeroPoolHandle, types::SettlementPathKey};
use crate::{
    interop::settler::{SettlementError, layerzero::contracts::ILayerZeroEndpointV2},
    transactions::{RelayTransaction, TransactionServiceHandle, TransactionStatus, TxId},
    types::{Call3, LZChainConfigs, TransactionServiceHandles, aggregate3Call},
};
use alloy::{
    primitives::{B256, ChainId},
    providers::{MULTICALL3_ADDRESS, Provider},
    rpc::types::TransactionRequest,
    sol_types::SolCall,
};
use std::time::Duration;
use tokio::time::interval;
use tracing::{error, info};

/// Processor monitoring and executing LayerZero settlement batches.
#[derive(Debug, Clone)]
pub struct LayerZeroBatchProcessor {
    /// Chain configurations
    chain_configs: LZChainConfigs,
    /// Handle to communicate with batch pool
    pool_handle: LayerZeroPoolHandle,
    /// Transaction service handles for all chains
    tx_service_handles: TransactionServiceHandles,
}

impl LayerZeroBatchProcessor {
    /// Create a new LayerZero batch processor.
    pub fn new(
        chain_configs: LZChainConfigs,
        pool_handle: LayerZeroPoolHandle,
        tx_service_handles: TransactionServiceHandles,
    ) -> Self {
        Self { chain_configs, pool_handle, tx_service_handles }
    }

    /// Spawn a processor for a specific settlement path.
    pub fn spawn_for_settlement_path(&self, key: SettlementPathKey) {
        if let Some(tx_service_handle) = self.tx_service_handles.get(&key.chain_id).cloned() {
            let processor = self.clone();
            tokio::spawn(async move {
                info!(
                    chain_id = key.chain_id,
                    src_eid = key.src_eid,
                    settler_address = ?key.settler_address,
                    "Spawning processor for settlement path"
                );
                processor.process_settlement_path(tx_service_handle, key).await;
            });
        } else {
            error!(chain_id = key.chain_id, "No transaction service handle available for chain");
        }
    }

    /// Process batches for a specific settlement path.
    pub async fn process_settlement_path(
        &self,
        tx_service_handle: TransactionServiceHandle,
        key: SettlementPathKey,
    ) {
        let mut interval = interval(Duration::from_millis(200));

        // Subscribe to pool size updates for this chain pair
        let mut pool_size_watcher = self.pool_handle.subscribe(key).await.expect("should exist");

        info!(
            chain_id = key.chain_id,
            src_eid = key.src_eid,
            settler_address = ?key.settler_address,
            "Starting batch processor for settlement path"
        );

        loop {
            // Process next batch for this chain pair
            if let Err(e) = self.process_next_batch(&tx_service_handle, key).await {
                error!(
                    chain_id = key.chain_id,
                    src_eid = key.src_eid,
                    settler_address = ?key.settler_address,
                    error = ?e,
                    "Failed to process batch for settlement path"
                );
            }

            // Wait for next processing trigger
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // Regular interval check - always process
                        break;
                    }
                    Ok(()) = pool_size_watcher.changed() => {
                        let pool_size = *pool_size_watcher.borrow();
                        if pool_size >= super::MAX_SETTLEMENTS_PER_BATCH {
                            info!(
                                chain_id = key.chain_id,
                                src_eid = key.src_eid,
                                pool_size = pool_size,
                                "Pool has enough messages, processing immediately"
                            );
                            break;
                        }
                        // Pool changed but not enough messages, keep waiting
                    }
                }
            }
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
        key: SettlementPathKey,
    ) -> Result<(), SettlementError> {
        // Get the highest nonce for this chain/eid
        let current_nonce = if let Some(nonce) = self.pool_handle.get_highest_nonce(key).await {
            nonce
        } else {
            // No batches sent yet, get from chain
            self.get_current_inbound_nonce(key).await?
        };

        // Get the gapless batch starting from current_nonce
        let mut pending_batch = self.pool_handle.get_pending_batch(key, current_nonce).await;

        // If batch is empty but we have pending messages, check if we have a nonce mismatch
        if pending_batch.is_empty() && pending_batch.total_pool_available > 0 {
            info!(
                chain_id = key.chain_id,
                src_eid = key.src_eid,
                total_available = pending_batch.total_pool_available,
                current_nonce = current_nonce,
                "No gapless batch found but many pending messages, checking chain nonce"
            );

            let chain_nonce = self.get_current_inbound_nonce(key).await?;
            if chain_nonce != current_nonce {
                info!(
                    chain_id = key.chain_id,
                    src_eid = key.src_eid,
                    pool_nonce = current_nonce,
                    chain_nonce = chain_nonce,
                    "Nonce mismatch detected, retrying with chain nonce"
                );

                // Try again with the chain nonce
                pending_batch = self.pool_handle.get_pending_batch(key, chain_nonce).await;
            }
        }

        if pending_batch.is_empty() {
            return Ok(());
        }

        info!(
            chain_id = key.chain_id,
            src_eid = key.src_eid,
            batch_size = pending_batch.len(),
            total_available = pending_batch.total_pool_available,
            start_nonce = pending_batch.settlements.first().unwrap().nonce,
            "Building LayerZero batch"
        );

        // Create and queue batch transaction
        let batch_tx =
            self.create_batch_transaction(key.chain_id, &pending_batch.settlements).await?;
        let tx_id = batch_tx.id;
        let last_nonce = pending_batch.settlements.last().unwrap().nonce;

        // Send transaction and don't wait for the status updates
        let _ = tx_service_handle.send_transaction_no_queue(batch_tx);

        // Wait for transaction to complete
        self.wait_for_transaction(tx_service_handle, tx_id, key, last_nonce).await
    }

    /// Wait for transaction confirmation and update pool state.
    async fn wait_for_transaction(
        &self,
        tx_service_handle: &TransactionServiceHandle,
        tx_id: TxId,
        key: SettlementPathKey,
        highest_nonce: u64,
    ) -> Result<(), SettlementError> {
        info!(
            chain_id = key.chain_id,
            src_eid = key.src_eid,
            tx_id = %tx_id,
            "Waiting for transaction to be confirmed"
        );

        let status = tx_service_handle.wait_for_tx(tx_id).await.map_err(|e| {
            error!(
                chain_id = key.chain_id,
                src_eid = key.src_eid,
                tx_id = %tx_id,
                error = ?e,
                "Failed to wait for transaction"
            );
            SettlementError::InternalError(format!("Failed to wait for transaction: {e:?}"))
        })?;

        match status {
            TransactionStatus::Confirmed(_) => {
                info!(
                    chain_id = key.chain_id,
                    src_eid = key.src_eid,
                    tx_id = %tx_id,
                    highest_nonce = highest_nonce,
                    "Transaction confirmed, updating highest nonce"
                );

                // Update highest nonce (also removes processed entries)
                self.pool_handle.update_highest_nonce(key, highest_nonce, tx_id).await;

                Ok(())
            }
            TransactionStatus::Failed(reason) => {
                error!(
                    chain_id = key.chain_id,
                    src_eid = key.src_eid,
                    tx_id = %tx_id,
                    reason = ?reason,
                    "Transaction failed"
                );
                Err(SettlementError::InternalError(format!("Transaction failed: {reason:?}")))
            }
            status => {
                error!(
                    chain_id = key.chain_id,
                    src_eid = key.src_eid,
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
        let config = self.chain_configs.ensure_chain_config(chain_id)?;

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
        key: SettlementPathKey,
    ) -> Result<u64, SettlementError> {
        let config = self.chain_configs.ensure_chain_config(key.chain_id)?;

        // Query the endpoint for the current inbound nonce
        let endpoint = ILayerZeroEndpointV2::new(config.endpoint_address, &config.provider);

        // Get the peer address for the source endpoint
        // TODO(joshie): Once contracts team fixes peers() endpoint to return the real peer,
        // use the commented code below instead of using key.settler_address as the sender (eg.
        // Katana has a different settler address)
        //
        // let sender = ILayerZeroSettler::new(key.settler_address, &config.provider)
        //     .peers(key.src_eid)
        //     .call()
        //     .await
        //     .map_err(|e| SettlementError::InternalError(e.to_string()))?;
        let sender = B256::left_padding_from(key.settler_address.as_slice());

        let nonce = endpoint
            .inboundNonce(key.settler_address, key.src_eid, sender)
            .call()
            .await
            .map_err(|e| SettlementError::InternalError(e.to_string()))?;

        Ok(nonce)
    }
}
