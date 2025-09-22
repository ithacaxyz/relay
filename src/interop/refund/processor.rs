//! Refund processing module for handling escrow refunds in interop bundles.
//!
//! This module provides functionality for building, sending, and monitoring refund
//! transactions for failed cross-chain settlements.

use crate::{
    error::StorageError,
    interop::escrow::EscrowDetails,
    storage::{RelayStorage, StorageApi},
    transactions::{
        RelayTransaction, TxId,
        interop::{BundleStatus, InteropBundle},
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

/// Errors that can occur during refund processing
#[derive(Debug, thiserror::Error)]
pub enum RefundProcessorError {
    /// Storage error
    #[error(transparent)]
    Storage(#[from] StorageError),

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
    /// Providers for each chain to estimate gas
    providers: HashMap<ChainId, DynProvider>,
}

impl RefundProcessor {
    /// Creates a new refund processor
    pub fn new(storage: RelayStorage, providers: HashMap<ChainId, DynProvider>) -> Self {
        Self { storage, providers }
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

        // For tests: if the the refund is done at the exact time it will fail. So we delay by one
        // second.
        let refund_timestamp = chrono::DateTime::from_timestamp(timestamp_secs + 1, 0)
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
    pub async fn build_missing_refunds(
        &self,
        bundle: &InteropBundle,
        escrow_details: &[EscrowDetails],
    ) -> Result<RefundTransactions, RefundProcessorError> {
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
            return Ok(RefundTransactions {
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
        let new_refund_txs = self.build_refund_transactions(&escrows_needing_refunds).await?;

        info!(
            bundle_id = ?bundle.id,
            new_tx_count = new_refund_txs.len(),
            escrows_needing_refunds = escrows_needing_refunds.len(),
            "Built refund transactions for missing escrows"
        );

        Ok(RefundTransactions { new_refund_txs, failed_tx_ids: existing_refunds.failed_tx_ids })
    }

    /// Get escrow details from confirmed source transactions.
    pub async fn get_confirmed_escrows(
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
            .flatten()
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
        escrows_needing_refunds: &[&EscrowDetails],
    ) -> Result<Vec<RelayTransaction>, RefundProcessorError> {
        let new_refund_txs = try_join_all(escrows_needing_refunds.iter().map(async |escrow| {
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

            let refund_tx = RelayTransaction::new_internal(
                escrow.escrow_address,
                input,
                escrow.chain_id,
                gas_limit,
            );

            Ok::<_, RefundProcessorError>(refund_tx)
        }))
        .await?;

        Ok(new_refund_txs)
    }
}

/// Result of building refund transactions for escrows that need them.
///
/// This includes both new refund transactions for escrows that don't have any,
/// as well as information about failed refund transactions that should be removed.
#[derive(Debug)]
pub struct RefundTransactions {
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
