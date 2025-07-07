//! Refund processing module for handling escrow refunds in interop bundles.
//!
//! This module provides functionality for building, sending, and monitoring refund
//! transactions for failed cross-chain settlements.

use crate::{
    error::StorageError,
    interop::escrow::EscrowDetails,
    storage::{RelayStorage, StorageApi},
    transactions::{
        RelayTransaction, TransactionServiceHandle, TxId,
        interop::{BundleStatus, BundleWithStatus, InteropBundle},
    },
    types::{IEscrow, rpc::BundleId},
};
use alloy::{
    primitives::{Address, B256, ChainId, map::HashMap},
    providers::{DynProvider, Provider},
    rpc::types::TransactionRequest,
    sol_types::SolCall,
};
use futures_util::future::try_join_all;
use std::collections::HashSet;
use tracing::{error, info, instrument};

/// Maximum number of retry attempts for refund processing.
/// 60 attempts * 5 seconds = 5 minutes maximum wait time.
const MAX_REFUND_RETRY_ATTEMPTS: u32 = 60;

/// Delay between refund retry attempts in seconds.
const REFUND_RETRY_DELAY_SECS: u64 = 5;

/// Fallback gas limit for refund transactions when estimation fails.
/// This should be sufficient for most refund operations.
const REFUND_FALLBACK_GAS_LIMIT: u64 = 1_000_000;

/// Errors that can occur during refund processing
#[derive(Debug, thiserror::Error)]
pub enum RefundProcessorError {
    /// Storage error
    #[error(transparent)]
    Storage(#[from] StorageError),

    /// No transaction service found for chain
    #[error("no transaction service for chain {0}")]
    NoTransactionService(ChainId),

    /// Failed to wait for transaction
    #[error("failed to wait for transaction: {0}")]
    WaitForTransaction(#[from] crate::transactions::TransactionServiceError),

    /// Execution failed with a specific error message
    #[error("execution failed: {0}")]
    ExecutionFailed(String),

    /// Invalid refund timestamp
    #[error("invalid refund timestamp: timestamp value is out of valid range")]
    InvalidRefundTimestamp,

    /// Maximum retry attempts reached
    #[error(
        "maximum refund retry attempts reached for bundle {bundle_id} after {attempts} attempts"
    )]
    MaxRetriesReached {
        /// The bundle ID that failed
        bundle_id: BundleId,
        /// Number of attempts made
        attempts: u32,
    },
}

/// Processor for handling refund transactions
///
/// ## Order
///
/// 1. **`schedule_refunds()`** - Called when source/destination failures occur
///    - Schedules refunds for future processing
///    - Transitions bundle to `RefundsScheduled` status
///
/// 2. **`queue_refunds()`** - Called when bundle reaches `RefundsReady` status
///    - Builds and sends initial refund transactions
///    - Transitions bundle to `RefundsQueued` status
///
/// 3. **`monitor_and_process_refunds()`** - Called when bundle is in `RefundsQueued` status
///    - Monitors refund transactions and retries failures
///    - Loops until all refunds complete or max retries reached
///    - Returns when all refunds are successful
#[derive(Debug)]
pub struct RefundProcessor {
    /// Storage for accessing bundle and transaction data
    storage: RelayStorage,
    /// Transaction service handles for sending transactions
    tx_service_handles: HashMap<ChainId, TransactionServiceHandle>,
    /// Providers for each chain to estimate gas
    providers: HashMap<ChainId, DynProvider>,
}

impl RefundProcessor {
    /// Creates a new refund processor
    pub fn new(
        storage: RelayStorage,
        tx_service_handles: HashMap<ChainId, TransactionServiceHandle>,
        providers: HashMap<ChainId, DynProvider>,
    ) -> Self {
        Self { storage, tx_service_handles, providers }
    }

    /// Get the transaction service handle for a specific chain.
    fn tx_service(
        &self,
        chain_id: ChainId,
    ) -> Result<&TransactionServiceHandle, RefundProcessorError> {
        self.tx_service_handles
            .get(&chain_id)
            .ok_or(RefundProcessorError::NoTransactionService(chain_id))
    }

    /// Schedule refunds for confirmed escrows in a bundle
    ///
    /// This method extracts escrow details from confirmed source transactions,
    /// calculates the maximum refund timestamp, and schedules the refunds.
    ///
    /// If refunds are successfully scheduled, updates the bundle status to RefundsScheduled.
    /// If no escrows are found, the bundle status remains unchanged.
    #[instrument(skip(self, bundle), fields(bundle_id = %bundle.bundle.id))]
    pub async fn schedule_refunds(
        &self,
        bundle: &mut BundleWithStatus,
    ) -> Result<(), RefundProcessorError> {
        // Get escrow details from confirmed source transactions
        let escrow_details = self.get_confirmed_escrows(&bundle.bundle).await?;

        // Check if we have any escrows to refund
        if escrow_details.is_empty() {
            info!("No escrows to refund");
            return Ok(());
        }

        // Calculate the maximum refund timestamp from all escrows
        let max_refund_timestamp =
            escrow_details.iter().map(|details| details.escrow.refundTimestamp).max().ok_or_else(
                || {
                    RefundProcessorError::ExecutionFailed(
                        "No refund timestamps found in escrows".to_string(),
                    )
                },
            )?;

        // Convert U256 timestamp to DateTime<Utc>
        // Ensure the timestamp is within valid range for i64
        let timestamp_secs: i64 = max_refund_timestamp
            .try_into()
            .map_err(|_| RefundProcessorError::InvalidRefundTimestamp)?;
        let refund_timestamp = chrono::DateTime::from_timestamp(timestamp_secs, 0)
            .ok_or(RefundProcessorError::InvalidRefundTimestamp)?;

        // Store pending refund and atomically update status
        self.storage
            .store_pending_refund(
                bundle.bundle.id,
                refund_timestamp,
                BundleStatus::RefundsScheduled,
            )
            .await?;

        // Update bundle status
        bundle.status = BundleStatus::RefundsScheduled;

        info!(
            bundle_id = ?bundle.bundle.id,
            refund_at = ?refund_timestamp,
            escrow_count = escrow_details.len(),
            "Stored pending refund and updated bundle status"
        );

        Ok(())
    }

    /// Build refund transactions for escrows that don't have them yet.
    ///
    /// This method modifies the bundle by removing any failed refund transactions
    /// before building new ones.
    #[instrument(skip(self, bundle, escrow_details), fields(
        bundle_id = %bundle.id,
        escrow_count = escrow_details.len()
    ))]
    async fn build_missing_refunds(
        &self,
        bundle: &mut InteropBundle,
        escrow_details: &[EscrowDetails],
    ) -> Result<Vec<RelayTransaction>, RefundProcessorError> {
        // Build mapping of escrow IDs to source transaction IDs
        let escrow_to_source_tx: HashMap<B256, TxId> = bundle
            .src_txs
            .iter()
            .filter_map(|tx| {
                tx.extract_escrow_details()
                    .filter(|escrow| escrow_details.iter().any(|e| e.escrow_id == escrow.escrow_id))
                    .map(|escrow| (escrow.escrow_id, tx.id))
            })
            .collect();

        let refunded_escrow_ids = self.process_existing_refund_transactions(bundle).await?;

        // Find escrows that need refund transactions
        let escrows_needing_refunds: Vec<_> = escrow_details
            .iter()
            .filter(|escrow| !refunded_escrow_ids.contains(&escrow.escrow_id))
            .collect();

        if escrows_needing_refunds.is_empty() {
            info!(
                bundle_id = ?bundle.id,
                "All escrows already have refund transactions"
            );
            return Ok(Vec::new());
        }

        info!(
            bundle_id = ?bundle.id,
            missing_count = escrows_needing_refunds.len(),
            total_escrows = escrow_details.len(),
            "Building refund transactions for escrows without them"
        );

        // Build new refund transactions
        let new_refund_txs =
            self.build_refund_transactions(&escrow_to_source_tx, &escrows_needing_refunds).await?;

        info!(
            bundle_id = ?bundle.id,
            new_tx_count = new_refund_txs.len(),
            escrows_needing_refunds = escrows_needing_refunds.len(),
            "Built refund transactions for missing escrows"
        );

        Ok(new_refund_txs)
    }

    /// Queue refunds by getting escrow details and building/sending transactions.
    ///
    /// This is a complete flow that:
    /// 1. Gets confirmed escrow details from the bundle
    /// 2. Builds and sends missing refund transactions
    /// 3. Updates bundle status to RefundsQueued
    ///
    /// ### Arguments
    /// * `bundle` - The bundle to process (will be modified with new refund_txs and status)
    ///
    /// ### Returns
    /// * `Ok(())` - If refunds were processed successfully
    /// * `Err(RefundProcessorError)` - If no escrows found or processing fails
    pub async fn queue_refunds(
        &self,
        bundle: &mut BundleWithStatus,
    ) -> Result<(), RefundProcessorError> {
        // Get escrow details from confirmed source transactions
        let escrow_details = self.get_confirmed_escrows(&bundle.bundle).await?;

        if escrow_details.is_empty() {
            return Err(RefundProcessorError::ExecutionFailed(
                "No escrow details found for refund processing".to_string(),
            ));
        }

        info!(
            bundle_id = ?bundle.bundle.id,
            escrow_count = escrow_details.len(),
            "Processing ready refunds"
        );

        // Build and send missing refunds
        self.build_and_send_missing_refunds(bundle, &escrow_details).await
    }

    /// Build and send refund transactions for escrows that don't have them yet
    ///
    /// This method handles the complete refund flow:
    /// 1. Builds refund transactions for escrows that don't have them
    /// 2. Updates the bundle's refund_txs field with the new transactions
    /// 3. Updates storage with the bundle status to RefundsQueued and queues the transactions
    /// 4. Updates the bundle's status field to RefundsQueued
    /// 5. Sends the transactions to the transaction service
    ///
    /// ### Arguments
    /// * `bundle` - The bundle to process (will be modified with new refund_txs and status)
    /// * `escrow_details` - List of escrow details from confirmed source transactions
    ///
    /// ### Returns
    /// * `Ok(())` - If the complete flow succeeds (even if no new transactions were needed)
    /// * `Err(RefundProcessorError)` - If any step in the flow fails
    #[instrument(skip(self, bundle, escrow_details), fields(
        bundle_id = %bundle.bundle.id,
        escrow_count = escrow_details.len()
    ))]
    async fn build_and_send_missing_refunds(
        &self,
        bundle: &mut BundleWithStatus,
        escrow_details: &[EscrowDetails],
    ) -> Result<(), RefundProcessorError> {
        // Build the refund transactions first
        let new_refund_txs = self.build_missing_refunds(&mut bundle.bundle, escrow_details).await?;

        if !new_refund_txs.is_empty() {
            let original_len = bundle.bundle.refund_txs.len();
            bundle.bundle.refund_txs.extend(new_refund_txs.clone());

            // Update storage with RefundsQueued status and queue transactions
            self.storage
                .update_bundle_and_queue_transactions(
                    &bundle.bundle,
                    BundleStatus::RefundsQueued,
                    &new_refund_txs,
                )
                .await
                .inspect_err(|_| bundle.bundle.refund_txs.truncate(original_len))?;

            // Update the bundle's status field only after successful storage update
            bundle.status = BundleStatus::RefundsQueued;

            // Send the transactions after database is updated
            self.send_transactions(&new_refund_txs).await?;

            info!(
                bundle_id = ?bundle.bundle.id,
                new_tx_count = new_refund_txs.len(),
                "Built, queued, and sent refund transactions"
            );
        } else {
            // No new transactions but we might need to update status
            // This handles the case where all refunds are already built
            self.storage
                .update_pending_bundle_status(bundle.bundle.id, BundleStatus::RefundsQueued)
                .await?;

            // Update the bundle's status field
            bundle.status = BundleStatus::RefundsQueued;

            info!(
                bundle_id = ?bundle.bundle.id,
                "No new refund transactions needed, updated bundle status"
            );
        }

        Ok(())
    }

    /// Watch refund transactions until they complete and return failed tx IDs
    #[instrument(skip(self, refund_txs), fields(tx_count = refund_txs.len()))]
    async fn watch_and_collect_failed_refunds(
        &self,
        refund_txs: &[RelayTransaction],
    ) -> Result<Vec<TxId>, RefundProcessorError> {
        let results = try_join_all(refund_txs.iter().map(async |tx| {
            let tx_service = self.tx_service(tx.chain_id())?;
            let status = tx_service.wait_for_tx(tx.id).await?;
            Ok::<_, RefundProcessorError>((tx.id, status))
        }))
        .await?;

        let failed_tx_ids: Vec<TxId> = results
            .into_iter()
            .filter_map(|(tx_id, status)| {
                if status.is_failed() {
                    error!(tx_id = ?tx_id, "Refund transaction failed");
                    Some(tx_id)
                } else {
                    None
                }
            })
            .collect();

        Ok(failed_tx_ids)
    }

    /// Monitor and process refund transactions for a bundle
    ///
    /// This method handles the complete refund monitoring flow:
    /// 1. Gets confirmed escrow details from the bundle
    /// 2. Watches all refund transactions and collects failed ones
    /// 3. If all succeed and all escrows are refunded, returns Ok(())
    /// 4. If some fail or escrows are missing refunds, rebuilds and sends them
    /// 5. Keeps retrying until all refunds complete or max retries reached
    ///
    /// ### Arguments
    /// * `bundle` - The bundle to process (will be modified with new refund_txs and status if
    ///   needed)
    ///
    /// ### Returns
    /// * `Ok(())` - All refunds completed successfully
    /// * `Err(RefundProcessorError)` - If monitoring or processing fails after max retries
    #[instrument(skip(self, bundle), fields(
        bundle_id = %bundle.bundle.id,
        refund_tx_count = bundle.bundle.refund_txs.len()
    ))]
    pub async fn monitor_and_process_refunds(
        &self,
        bundle: &mut BundleWithStatus,
    ) -> Result<(), RefundProcessorError> {
        info!(bundle_id = ?bundle.bundle.id, "Monitoring refund transactions");

        let mut retry_count = 0;

        // Get all confirmed escrow details from the bundle
        let escrow_details = self.get_confirmed_escrows(&bundle.bundle).await?;

        loop {
            // Watch all refund transactions until completion and collect failed ones
            let failed_tx_ids =
                self.watch_and_collect_failed_refunds(&bundle.bundle.refund_txs).await?;

            if failed_tx_ids.is_empty() {
                info!(
                    bundle_id = ?bundle.bundle.id,
                    "All refund transactions succeeded and all escrows refunded"
                );
                return Ok(());
            }

            // Some refunds failed, rebuild them
            info!(
                bundle_id = ?bundle.bundle.id,
                failed_count = failed_tx_ids.len(),
                "Some refund transactions failed, rebuilding them"
            );

            self.build_and_send_missing_refunds(bundle, &escrow_details).await?;

            retry_count += 1;
            if retry_count >= MAX_REFUND_RETRY_ATTEMPTS {
                error!(
                    bundle_id = ?bundle.bundle.id,
                    retry_count,
                    "Maximum refund retry attempts reached"
                );
                return Err(RefundProcessorError::MaxRetriesReached {
                    bundle_id: bundle.bundle.id,
                    attempts: retry_count,
                });
            }

            // Wait before checking again to avoid busy looping
            info!(
                bundle_id = ?bundle.bundle.id,
                retry_count,
                max_retries = MAX_REFUND_RETRY_ATTEMPTS,
                "Some refunds still processing, waiting before retry"
            );
            tokio::time::sleep(std::time::Duration::from_secs(REFUND_RETRY_DELAY_SECS)).await;
        }
    }

    /// Get escrow details from confirmed source transactions.
    async fn get_confirmed_escrows(
        &self,
        bundle: &InteropBundle,
    ) -> Result<Vec<EscrowDetails>, RefundProcessorError> {
        let results = try_join_all(bundle.src_txs.iter().map(async |tx| {
            let status = self.storage.read_transaction_status(tx.id).await?;
            Ok::<_, StorageError>((tx, status))
        }))
        .await
        .map_err(RefundProcessorError::Storage)?;

        // Process results - only extract from confirmed transactions
        Ok(results
            .into_iter()
            .filter_map(|(tx, status_result)| {
                status_result
                    .filter(|(_, status)| status.is_confirmed())
                    .and_then(|_| tx.extract_escrow_details())
            })
            .collect())
    }

    /// Process existing refund transactions in one pass:
    ///
    /// This method modifies the bundle by removing failed refund transactions,
    /// ensuring only successful or pending refunds remain in the bundle.
    async fn process_existing_refund_transactions(
        &self,
        bundle: &mut InteropBundle,
    ) -> Result<HashSet<B256>, RefundProcessorError> {
        let results = try_join_all(bundle.refund_txs.iter().map(async |tx| {
            let status = self.storage.read_transaction_status(tx.id).await?;
            Ok::<_, StorageError>((tx, status))
        }))
        .await
        .map_err(RefundProcessorError::Storage)?;

        let mut refunded_escrow_ids = HashSet::new();
        let mut failed_tx_ids = Vec::new();

        // Process results
        for (refund_tx, status_result) in results {
            if let Some((_, status)) = status_result {
                if status.is_failed() {
                    failed_tx_ids.push(refund_tx.id);
                } else {
                    // Extract escrow IDs from successful or pending transactions
                    refunded_escrow_ids.extend(refund_tx.escrow_ids());
                }
            }
        }

        // Remove failed transactions
        bundle.refund_txs.retain(|tx| !failed_tx_ids.contains(&tx.id));

        Ok(refunded_escrow_ids)
    }

    /// Build refund transactions for escrows that need them
    async fn build_refund_transactions(
        &self,
        escrow_to_source_tx: &HashMap<B256, TxId>,
        escrows_needing_refunds: &[&EscrowDetails],
    ) -> Result<Vec<RelayTransaction>, RefundProcessorError> {
        let new_refund_txs = try_join_all(escrows_needing_refunds.iter().map(async |escrow| {
            let source_tx_id =
                escrow_to_source_tx.get(&escrow.escrow_id).copied().ok_or_else(|| {
                    RefundProcessorError::ExecutionFailed(format!(
                        "Could not find source transaction ID for escrow {:?}",
                        escrow.escrow_id
                    ))
                })?;

            let input = IEscrow::refundCall { escrowIds: vec![escrow.escrow_id] }.abi_encode();

            // Estimate gas for the refund transaction
            let gas_limit = if let Some(provider) = self.providers.get(&escrow.chain_id) {
                let tx_request = TransactionRequest {
                    from: Some(Address::ZERO),
                    to: Some(escrow.escrow_address.into()),
                    input: input.clone().into(),
                    ..Default::default()
                };

                provider
                    .estimate_gas(tx_request)
                    .await
                    .map(|estimated| {
                        // Add 20% buffer to the estimate for safety
                        estimated.saturating_mul(120).saturating_div(100)
                    })
                    .unwrap_or_else(|e| {
                        error!(
                            chain_id = ?escrow.chain_id,
                            escrow_address = ?escrow.escrow_address,
                            error = ?e,
                            "Failed to estimate gas for refund transaction, using fallback"
                        );
                        REFUND_FALLBACK_GAS_LIMIT
                    })
            } else {
                REFUND_FALLBACK_GAS_LIMIT
            };

            let refund_tx = RelayTransaction::new_refund(
                source_tx_id,
                escrow.escrow_address.into(),
                input.into(),
                escrow.chain_id,
                gas_limit,
            );

            Ok::<_, RefundProcessorError>(refund_tx)
        }))
        .await?;

        Ok(new_refund_txs)
    }

    /// Send transactions to the transaction service.
    ///
    /// This method assumes transactions have already been queued in storage.
    /// It only sends them to the transaction service for execution.
    async fn send_transactions(
        &self,
        transactions: &[RelayTransaction],
    ) -> Result<(), RefundProcessorError> {
        for tx in transactions {
            self.tx_service(tx.chain_id())?.send_transaction_no_queue(tx.clone());
        }

        Ok(())
    }
}
