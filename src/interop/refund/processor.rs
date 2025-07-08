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

/// Maximum number of retry attempts for failed refund transactions.
pub const MAX_REFUND_RETRY_ATTEMPTS: u32 = 5;

/// Fallback gas limit for refund transactions when estimation fails.
/// This should be sufficient for most refund operations.
const REFUND_FALLBACK_GAS_LIMIT: u64 = 1_000_000;

/// Updates to apply to the in-memory bundle after queueing refunds
#[derive(Debug, Clone)]
pub struct RefundUpdate {
    /// New refund transactions to add to the bundle
    pub new_refund_txs: Vec<RelayTransaction>,
    /// Transaction IDs to remove from refund_txs
    pub failed_tx_ids: Vec<TxId>,
    /// New bundle status
    pub new_status: Option<BundleStatus>,
}

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
    /// Storage: If there is any pending refund, updates the bundle status to `RefundsScheduled`
    ///
    /// Returns `Some(RefundsScheduled)` or `None` if no escrows found.
    #[instrument(skip(self, bundle), fields(bundle_id = %bundle.id))]
    pub async fn schedule_refunds(
        &self,
        bundle: &InteropBundle,
    ) -> Result<Option<BundleStatus>, RefundProcessorError> {
        // Get escrow details from confirmed source transactions
        let escrow_details = self.get_confirmed_escrows(bundle).await?;

        // Check if we have any escrows to refund
        if escrow_details.is_empty() {
            info!("No escrows to refund");
            return Ok(None);
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
            .store_pending_refund(bundle.id, refund_timestamp, BundleStatus::RefundsScheduled)
            .await?;

        info!(
            bundle_id = ?bundle.id,
            refund_at = ?refund_timestamp,
            escrow_count = escrow_details.len(),
            "Stored pending refund and updated bundle status"
        );

        Ok(Some(BundleStatus::RefundsScheduled))
    }

    /// Build refund transactions for confirmed escrows that are missing them.
    ///
    /// Every confirmed source transaction with escrow details must have a corresponding
    /// refund transaction. This method identifies escrows from confirmed source transactions
    /// that don't have confirmed refund transactions yet and builds them.
    ///
    /// Returns the new refund transactions to add and the IDs of failed transactions to remove.
    #[instrument(skip(self, bundle, escrow_details), fields(
        bundle_id = %bundle.id,
        escrow_count = escrow_details.len()
    ))]
    async fn build_missing_refunds(
        &self,
        bundle: &InteropBundle,
        escrow_details: &[EscrowDetails],
    ) -> Result<RefundsReplacements, RefundProcessorError> {
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

        let existing_refunds = self.process_existing_refund_transactions(bundle).await?;

        // Find escrows that need refund transactions
        let escrows_needing_refunds: Vec<_> = escrow_details
            .iter()
            .filter(|escrow| !existing_refunds.refunded_escrow_ids.contains(&escrow.escrow_id))
            .collect();

        if escrows_needing_refunds.is_empty() {
            info!(
                bundle_id = ?bundle.id,
                "All escrows already have refund transactions"
            );
            return Ok(RefundsReplacements {
                new_refund_txs: Vec::new(),
                failed_tx_ids: existing_refunds.failed_tx_ids,
            });
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

        Ok(RefundsReplacements { new_refund_txs, failed_tx_ids: existing_refunds.failed_tx_ids })
    }

    /// Queue refunds by building and sending missing refund transactions
    ///
    /// Storage: Updates bundle with new refund transactions, queues them and updates status to
    /// `RefundsQueued`.
    ///
    /// Returns `RefundUpdate` to apply to in-memory bundle.
    pub async fn queue_refunds(
        &self,
        bundle: &BundleWithStatus,
    ) -> Result<RefundUpdate, RefundProcessorError> {
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
    /// Storage: Updates bundle with new refund transactions, queues them and updates status to
    /// `RefundsQueued`.
    ///
    /// ### Returns
    /// * `Ok(RefundUpdate)` - Updates to apply to the in-memory bundle
    /// * `Err(RefundProcessorError)` - If any step in the flow fails
    #[instrument(skip(self, bundle, escrow_details), fields(
        bundle_id = %bundle.bundle.id,
        escrow_count = escrow_details.len()
    ))]
    async fn build_and_send_missing_refunds(
        &self,
        bundle: &BundleWithStatus,
        escrow_details: &[EscrowDetails],
    ) -> Result<RefundUpdate, RefundProcessorError> {
        // Build the refund transactions first
        let refunds = self.build_missing_refunds(&bundle.bundle, escrow_details).await?;

        if !refunds.new_refund_txs.is_empty() {
            // Validate we have transaction services for all chains before touching storage
            for tx in &refunds.new_refund_txs {
                self.tx_service(tx.chain_id())?;
            }

            // Create updated bundle for storage
            let mut updated_bundle = bundle.bundle.clone();
            updated_bundle.refund_txs.retain(|tx| !refunds.failed_tx_ids.contains(&tx.id));
            updated_bundle.refund_txs.extend(refunds.new_refund_txs.clone());

            // Update storage with RefundsQueued status and queue transactions
            self.storage
                .update_bundle_and_queue_transactions(
                    &updated_bundle,
                    BundleStatus::RefundsQueued,
                    &refunds.new_refund_txs,
                )
                .await?;

            // Send the transactions after database is updated
            // This is now infallible since we validated tx services above
            for tx in &refunds.new_refund_txs {
                if let Some(tx_service) = self.tx_service_handles.get(&tx.chain_id()) {
                    tx_service.send_transaction_no_queue(tx.clone());
                }
            }

            info!(
                bundle_id = ?bundle.bundle.id,
                new_tx_count = refunds.new_refund_txs.len(),
                "Built, queued, and sent refund transactions"
            );
        } else {
            // No new transactions but we might need to update status
            // This handles the case where all refunds are already built
            self.storage
                .update_pending_bundle_status(bundle.bundle.id, BundleStatus::RefundsQueued)
                .await?;

            info!(
                bundle_id = ?bundle.bundle.id,
                "No new refund transactions needed, updated bundle status"
            );
        }

        Ok(RefundUpdate {
            new_refund_txs: refunds.new_refund_txs,
            failed_tx_ids: refunds.failed_tx_ids,
            new_status: Some(BundleStatus::RefundsQueued),
        })
    }

    /// Monitor refund transactions until they complete and return failed tx IDs
    #[instrument(skip(self, refund_txs), fields(tx_count = refund_txs.len()))]
    pub async fn monitor_refund_completion(
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

    /// Process existing refund transactions and return escrow IDs and failed transaction IDs.
    ///
    /// Returns [`ExistingRefunds`].
    async fn process_existing_refund_transactions(
        &self,
        bundle: &InteropBundle,
    ) -> Result<ExistingRefunds, RefundProcessorError> {
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

        Ok(ExistingRefunds { refunded_escrow_ids, failed_tx_ids })
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
                        // add 20% buffer
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
}

/// Failed refund transaction ids and their transaction replacements
#[derive(Debug)]
pub struct RefundsReplacements {
    /// New refund transactions to add
    pub new_refund_txs: Vec<RelayTransaction>,
    /// Transaction IDs that failed and should be removed
    pub failed_tx_ids: Vec<TxId>,
}

/// Result of analyzing existing refund transactions in a bundle.
///
/// This struct contains information about which escrows already have refund
/// transactions (either successful or pending) and which refund transactions
/// have failed and need to be replaced.
#[derive(Debug)]
pub struct ExistingRefunds {
    /// Escrow IDs that have successful or pending refund transactions
    pub refunded_escrow_ids: HashSet<B256>,
    /// Transaction IDs that have failed and should be removed
    pub failed_tx_ids: Vec<TxId>,
}
