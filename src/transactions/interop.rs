use super::{
    RelayTransaction, TransactionFailureReason, TransactionServiceError, TransactionServiceHandle,
    TransactionStatus, TxId,
};
use crate::{
    config::InteropConfig,
    error::StorageError,
    interop::{
        RefundMonitorService, RefundProcessor, RefundProcessorError, SettlementError,
        settler::{
            SettlerId, layerzero::types::LayerZeroPacketInfo, processor::SettlementProcessor,
        },
    },
    liquidity::{LiquidityTracker, LiquidityTrackerError},
    storage::{RelayStorage, StorageApi},
    types::{InteropTransactionBatch, OrchestratorContract::IntentExecuted, rpc::BundleId},
};
use alloy::{
    primitives::{Address, Bytes, ChainId, U256, map::HashMap},
    providers::{DynProvider, MulticallError},
    rpc::types::TransactionReceipt,
};
use futures_util::future::try_join_all;
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::sync::mpsc;
use tracing::{debug, error, instrument};

/// Asset transfer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetTransfer {
    /// The chain ID where the asset transfer occurs
    pub chain_id: ChainId,
    /// The address of the asset being transferred (0x0 for native token)
    pub asset_address: Address,
    /// The amount of the asset to transfer
    pub amount: U256,
    /// The transaction ID of the asset transfer
    pub tx_id: TxId,
}

/// Persistent bundle structure that stores full transaction data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteropBundle {
    /// Unique identifier for the bundle.
    pub id: BundleId,
    /// Settler implementation ID
    pub settler_id: SettlerId,
    /// Source chain transactions
    pub src_txs: Vec<RelayTransaction>,
    /// Destination chain transactions
    pub dst_txs: Vec<RelayTransaction>,
    /// Pre-calculated asset transfers for liquidity tracking
    pub asset_transfers: Vec<AssetTransfer>,
    /// Refund transactions (populated when src_txs fail)
    ///
    /// Only successful refund transactions are kept in the bundle.
    pub refund_txs: Vec<RelayTransaction>,
    /// Settlement transactions (populated after destination confirmation)
    pub settlement_txs: Vec<RelayTransaction>,
    /// Execute receive transactions required by the settler (e.g., LayerZero delivery txs).
    ///
    /// These are populated after verification steps if needed.
    pub execute_receive_txs: Vec<RelayTransaction>,
    /// Failed verification details for cross-chain messages
    ///
    /// If any verifications fail, this contains details about which messages couldn't be verified.
    /// When this is non-empty, the bundle should go to Failed state instead of Done.
    pub failed_verifications: Vec<LayerZeroPacketInfo>,
}

impl InteropBundle {
    /// Creates a new empty interop bundle with the given ID and settler
    pub fn new(id: BundleId, settler_id: SettlerId) -> Self {
        Self {
            id,
            settler_id,
            src_txs: Vec::new(),
            dst_txs: Vec::new(),
            asset_transfers: Vec::new(),
            refund_txs: Vec::new(),
            settlement_txs: Vec::new(),
            execute_receive_txs: Vec::new(),
            failed_verifications: vec![],
        }
    }

    /// Appends transactions to the appropriate field based on the transaction type.
    /// Only settlement-related transactions are appended (ExecuteSend, ExecuteReceive, Refund).
    /// Source and Destination transactions are assumed to already be in the bundle.
    pub fn append_transactions(&mut self, batch: &InteropTransactionBatch<'_>) {
        match batch {
            InteropTransactionBatch::Source(_) | InteropTransactionBatch::Destination(_) => {
                // These are already in the bundle, no need to append
            }
            InteropTransactionBatch::ExecuteSend(txs) => {
                self.settlement_txs.extend_from_slice(txs);
            }
            InteropTransactionBatch::ExecuteReceive(txs) => {
                self.execute_receive_txs.extend_from_slice(txs);
            }
            InteropTransactionBatch::Refund(txs) => {
                self.refund_txs.extend_from_slice(txs);
            }
        }
    }

    /// Appends a source transaction to the bundle.
    ///
    /// Source transactions contain escrow calls from build_escrow_calls that can be extracted using
    /// the transaction's extract_escrow_details() method.
    pub fn append_src(&mut self, tx: RelayTransaction) {
        self.src_txs.push(tx);
    }

    /// Appends a destination transaction to the bundle and extracts the asset fund transfers from
    /// the transaction's quote intent for liquidity tracking.
    pub fn append_dst(&mut self, tx: RelayTransaction) {
        // Calculate asset transfers for this transaction
        if let Some(transfers) = tx.quote().and_then(|q| q.intent.fund_transfers().ok()) {
            for (asset, amount) in transfers {
                self.asset_transfers.push(AssetTransfer {
                    chain_id: tx.chain_id(),
                    asset_address: asset,
                    amount,
                    tx_id: tx.id,
                });
            }
        }

        self.dst_txs.push(tx);
    }
}

/// Bundle with its current status
#[derive(Debug, Clone, derive_more::Deref, derive_more::DerefMut)]
pub struct BundleWithStatus {
    /// The interop bundle containing transaction data
    #[deref]
    #[deref_mut]
    pub bundle: InteropBundle,
    /// Current status of the bundle in the processing pipeline
    pub status: BundleStatus,
}

/// Errors that can occur during interop bundle processing.
#[derive(Debug, thiserror::Error)]
enum InteropBundleError {
    /// Transaction failed.
    #[error("transaction failed: {0}")]
    TransactionError(Arc<dyn TransactionFailureReason>),
    /// Errors returned by [`LiquidityTracker`].
    #[error(transparent)]
    Liquidity(#[from] LiquidityTrackerError),
    /// Invalid state transition
    #[error("invalid state transition from {from:?} to {to:?}")]
    InvalidStateTransition { from: BundleStatus, to: BundleStatus },
    /// Storage error.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// Refunds are not ready yet
    #[error("refunds not ready yet")]
    RefundsNotReady,
    /// Refund processor error.
    #[error(transparent)]
    RefundProcessor(#[from] RefundProcessorError),
    /// An error occurred during ABI encoding/decoding.
    #[error(transparent)]
    AbiError(#[from] alloy::sol_types::Error),
    /// Multicall error.
    #[error(transparent)]
    MulticallError(#[from] MulticallError),
    /// No transaction service found for chain.
    #[error("no transaction service for chain {0}")]
    NoTransactionService(ChainId),
    /// Failed to wait for transaction.
    #[error("failed to wait for transaction: {0}")]
    WaitForTransaction(#[from] TransactionServiceError),
    /// Intent execution failed with an error.
    #[error("intent execution failed: {0}")]
    IntentExecutionFailed(String),
    /// Intent executed event not found in receipt.
    #[error("IntentExecuted event not found in receipt")]
    IntentEventNotFound,
    /// Settlement processor error.
    #[error("settlement processor error: {0}")]
    SettlementProcessor(#[from] crate::interop::SettlementError),
}

/// Status of a pending interop bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "bundle_status", rename_all = "snake_case")]
pub enum BundleStatus {
    /// Initial state before any processing
    ///
    /// Next: [`Self::SourceQueued`]
    Init,
    /// Liquidity for destination transactions was locked.
    ///
    /// Next: [`Self::SourceQueued`]
    LiquidityLocked,
    /// Source transactions are queued
    ///
    /// Next: [`Self::SourceConfirmed`] OR [`Self::SourceFailures`]
    SourceQueued,
    /// Source transactions are confirmed
    ///
    /// Next: [`Self::DestinationQueued`]
    SourceConfirmed,
    /// Source transactions have failures
    ///
    /// Next: [`Self::RefundsScheduled`] OR [`Self::Failed`]
    SourceFailures,
    /// Destination transactions are queued
    ///
    /// Next: [`Self::DestinationConfirmed`] OR [`Self::DestinationFailures`]
    DestinationQueued,
    /// Destination transactions have failures
    ///
    /// Next: [`Self::RefundsScheduled`] OR [`Self::Failed`]
    DestinationFailures,
    /// Destination transactions are confirmed
    ///
    /// Next: [`Self::SettlementsQueued`]
    DestinationConfirmed,
    /// Settlement transactions are queued to be processed
    ///
    /// Next: [`Self::SettlementsProcessing`] OR [`Self::Failed`]
    SettlementsQueued,
    /// Additional settler-specific processing is in progress
    ///
    /// Next: [`Self::SettlementCompletionQueued`] OR [`Self::Done`]
    SettlementsProcessing,
    /// Settlement completion transactions are queued
    ///
    /// Next: [`Self::Done`] OR [`Self::Failed`]
    SettlementCompletionQueued,
    /// Refunds are scheduled for delayed execution
    ///
    /// Next: [`Self::RefundsReady`] OR stays in [`Self::RefundsScheduled`]
    RefundsScheduled,
    /// Refunds are ready to be processed (removed from scheduler)
    ///
    /// Next: [`Self::RefundsQueued`]
    RefundsReady,
    /// Refund transactions are queued and being monitored
    ///
    /// Next: [`Self::Done`] (after all refunds succeed) OR stays in `RefundsQueued` (while
    /// retrying)
    RefundsQueued,
    /// Bundle is completely done
    ///
    /// Terminal state
    Done,
    /// Bundle has failed and cannot be recovered
    ///
    /// Terminal state
    Failed,
}

impl BundleStatus {
    /// Whether status is [`Self::DestinationConfirmed`].
    pub fn is_destination_confirmed(&self) -> bool {
        matches!(self, Self::DestinationConfirmed)
    }

    /// Whether status is [`Self::DestinationFailures`].
    pub fn is_destination_failures(&self) -> bool {
        matches!(self, Self::DestinationFailures)
    }

    /// Whether status is [`Self::RefundsScheduled`].
    pub fn is_refunds_scheduled(&self) -> bool {
        matches!(self, Self::RefundsScheduled)
    }

    /// Check if this status can transition to another status
    pub fn can_transition_to(&self, next: &Self) -> bool {
        use BundleStatus::*;
        matches!(
            (self, next),
            (Init, LiquidityLocked)
                | (LiquidityLocked, SourceQueued)
                | (SourceQueued, SourceConfirmed)
                | (SourceQueued, SourceFailures)
                | (SourceConfirmed, DestinationQueued)
                | (SourceFailures, RefundsScheduled)
                | (SourceFailures, Failed)
                | (DestinationQueued, DestinationConfirmed)
                | (DestinationQueued, DestinationFailures)
                | (DestinationFailures, RefundsScheduled)
                | (DestinationFailures, Failed)
                | (DestinationConfirmed, SettlementsQueued)
                | (SettlementsQueued, SettlementsProcessing)
                | (SettlementsQueued, Failed)
                | (SettlementsProcessing, SettlementCompletionQueued)
                | (SettlementsProcessing, Done)
                | (SettlementCompletionQueued, Done)
                | (SettlementCompletionQueued, Failed)
                | (RefundsScheduled, RefundsReady)
                | (RefundsReady, RefundsQueued)
                | (RefundsQueued, Done)
                | (RefundsQueued, Failed)
        )
    }
}

impl From<Arc<dyn TransactionFailureReason>> for InteropBundleError {
    fn from(err: Arc<dyn TransactionFailureReason>) -> Self {
        Self::TransactionError(err)
    }
}

/// Messages that can be sent to the interop service.
#[derive(Debug)]
pub enum InteropServiceMessage {
    /// Send a bundle with status.
    SendBundleWithStatus(Box<BundleWithStatus>),
}

/// Handle to communicate with the [`InteropService`].
#[derive(Debug, Clone)]
pub struct InteropServiceHandle {
    command_tx: mpsc::UnboundedSender<InteropServiceMessage>,
    storage: RelayStorage,
    liquidity_tracker: LiquidityTracker,
    settlement_processor: Arc<SettlementProcessor>,
}

impl InteropServiceHandle {
    /// Sends an interop bundle to the service.
    ///
    /// It will also store the bundle to the storage.
    pub async fn send_bundle(&self, bundle: InteropBundle) -> Result<(), StorageError> {
        // Store the bundle with Init status
        self.storage.store_pending_bundle(&bundle, BundleStatus::Init).await?;

        // Send to service for processing
        self.send_bundle_with_status(BundleWithStatus { bundle, status: BundleStatus::Init });
        Ok(())
    }

    /// Sends a bundle with status to the service.
    pub fn send_bundle_with_status(&self, bundle: BundleWithStatus) {
        let _ = self.command_tx.send(InteropServiceMessage::SendBundleWithStatus(Box::new(bundle)));
    }

    /// Returns a handle to the liquidity tracker.
    pub fn liquidity_tracker(&self) -> &LiquidityTracker {
        &self.liquidity_tracker
    }

    /// Returns the settler address.
    pub fn settler_address(&self) -> Address {
        self.settlement_processor.settler_address()
    }

    /// Returns the settler ID.
    pub fn settler_id(&self) -> SettlerId {
        self.settlement_processor.settler_id()
    }

    /// Encodes the settler context for the given destination chains.
    pub fn encode_settler_context(
        &self,
        destination_chains: Vec<u64>,
    ) -> Result<Bytes, SettlementError> {
        self.settlement_processor.encode_settler_context(destination_chains)
    }
}

/// Internal state of the interop service.
#[derive(Debug)]
struct InteropServiceInner {
    tx_service_handles: HashMap<ChainId, TransactionServiceHandle>,
    liquidity_tracker: LiquidityTracker,
    storage: RelayStorage,
    refund_processor: RefundProcessor,
    settlement_processor: Arc<SettlementProcessor>,
    interop_config: InteropConfig,
}

impl InteropServiceInner {
    /// Creates a new interop service inner state.
    fn new(
        tx_service_handles: HashMap<ChainId, TransactionServiceHandle>,
        liquidity_tracker: LiquidityTracker,
        storage: RelayStorage,
        providers: HashMap<ChainId, DynProvider>,
        settlement_processor: Arc<SettlementProcessor>,
        interop_config: InteropConfig,
    ) -> Self {
        let refund_processor = RefundProcessor::new(storage.clone(), providers);
        Self {
            tx_service_handles,
            liquidity_tracker,
            storage,
            refund_processor,
            settlement_processor,
            interop_config,
        }
    }

    /// Helper to update bundle status in storage and locally
    #[instrument(skip(self, bundle), fields(
        bundle_id = %bundle.bundle.id,
        from = ?bundle.status,
        to = ?new_status
    ))]
    async fn update_bundle_status(
        &self,
        bundle: &mut BundleWithStatus,
        new_status: BundleStatus,
    ) -> Result<(), InteropBundleError> {
        // Validate state transition
        if !bundle.status.can_transition_to(&new_status) {
            return Err(InteropBundleError::InvalidStateTransition {
                from: bundle.status,
                to: new_status,
            });
        }

        self.storage.update_pending_bundle_status(bundle.bundle.id, new_status).await?;
        bundle.status = new_status;
        Ok(())
    }

    /// Handle the Init status - lock liquidity
    ///
    /// Transitions to: [`BundleStatus::LiquidityLocked`]
    async fn on_init(&self, bundle: &mut BundleWithStatus) -> Result<(), InteropBundleError> {
        tracing::info!(
            bundle_id = ?bundle.bundle.id,
            src_count = bundle.bundle.src_txs.len(),
            dst_count = bundle.bundle.dst_txs.len(),
            "Initializing bundle"
        );

        self.liquidity_tracker
            .try_lock_liquidity_for_bundle(&bundle.bundle, BundleStatus::LiquidityLocked)
            .await?;
        bundle.status = BundleStatus::LiquidityLocked;

        Ok(())
    }

    /// Handle the LiquidityLocked status - queue source transactions
    ///
    /// Transitions to: [`BundleStatus::SourceQueued`]
    async fn on_liquidity_locked(
        &self,
        bundle: &mut BundleWithStatus,
    ) -> Result<(), InteropBundleError> {
        tracing::info!(bundle_id = ?bundle.bundle.id, "Sending source transactions");

        // Queue and send source transactions
        bundle.status = self
            .queue_and_send_bundle_transactions(
                bundle,
                InteropTransactionBatch::Source(&bundle.bundle.src_txs),
            )
            .await?;

        Ok(())
    }

    /// Handle the SourceQueued status - wait for source transactions to complete
    ///
    /// Transitions to: [`BundleStatus::SourceConfirmed`] or [`BundleStatus::SourceFailures`]
    async fn on_source_queued(
        &self,
        bundle: &mut BundleWithStatus,
    ) -> Result<(), InteropBundleError> {
        tracing::info!(bundle_id = ?bundle.bundle.id, "Processing source transactions");

        // Wait for all source transactions to complete
        let results = self.watch_intent_transactions(bundle.bundle.src_txs.iter()).await?;

        let mut new_status = BundleStatus::SourceConfirmed;
        for (tx_id, result) in results {
            if result.is_err() {
                tracing::error!(tx_id = ?tx_id, bundle_id = ?bundle.bundle.id, "Source transaction failed");
                new_status = BundleStatus::SourceFailures;
                break;
            }
            tracing::debug!(tx_id = ?tx_id, "Source transaction succeeded");
        }

        self.update_bundle_status(bundle, new_status).await?;
        Ok(())
    }

    /// Handle the SourceConfirmed status - queue destination transactions
    ///
    /// Transitions to: [`BundleStatus::DestinationQueued`]
    async fn on_source_confirmed(
        &self,
        bundle: &mut BundleWithStatus,
    ) -> Result<(), InteropBundleError> {
        tracing::info!(bundle_id = ?bundle.bundle.id, "Sending destination transactions");

        // Queue and send destination transactions
        bundle.status = self
            .queue_and_send_bundle_transactions(
                bundle,
                InteropTransactionBatch::Destination(&bundle.bundle.dst_txs),
            )
            .await?;

        Ok(())
    }

    /// Handle bundles with source failures - schedule refunds for any successful source
    /// transactions
    ///
    /// Transitions to: [`BundleStatus::RefundsScheduled`] OR [`BundleStatus::Failed`]
    async fn on_source_failures(
        &self,
        bundle: &mut BundleWithStatus,
    ) -> Result<(), InteropBundleError> {
        tracing::warn!(
            bundle_id = ?bundle.bundle.id,
            "Handling source failures - checking for successful transactions to refund"
        );

        // Try to schedule refunds for any confirmed escrows
        if let Some(new_status) = self.refund_processor.schedule_refunds(&bundle.bundle).await? {
            bundle.status = new_status;
        } else {
            // No source transaction was confirmed, so no refunds need to be issued.
            self.update_bundle_status(bundle, BundleStatus::Failed).await?;
        }

        Ok(())
    }

    /// Handle the DestinationQueued status - wait for destination transactions to complete
    ///
    /// Transitions to: [`BundleStatus::DestinationConfirmed`] or
    /// [`BundleStatus::DestinationFailures`]
    async fn on_destination_queued(
        &self,
        bundle: &mut BundleWithStatus,
    ) -> Result<(), InteropBundleError> {
        tracing::info!(bundle_id = ?bundle.bundle.id, "Processing destination transactions");

        let (status, receipts) = self.process_destination_transactions(&bundle.bundle).await?;
        self.storage.unlock_bundle_liquidity(&bundle.bundle, receipts, status).await?;
        bundle.status = status;

        Ok(())
    }

    /// Handle bundles with destination failures - schedule refunds for successful source
    /// transactions
    ///
    /// Transitions to: [`BundleStatus::RefundsScheduled`] OR [`BundleStatus::Failed`]
    async fn on_destination_failures(
        &self,
        bundle: &mut BundleWithStatus,
    ) -> Result<(), InteropBundleError> {
        tracing::warn!(
            bundle_id = ?bundle.bundle.id,
            "Handling destination failures - scheduling refunds for escrows"
        );

        if let Some(new_status) = self.refund_processor.schedule_refunds(&bundle.bundle).await? {
            bundle.status = new_status;
        } else {
            // This should technically not happen, since we know all source confirmations have been
            // confirmed, otherwise we wouldn't have tried sending destination transactions.
            tracing::error!(status = ?bundle.status, "No escrows to refund, marking bundle as failed");
            self.update_bundle_status(bundle, BundleStatus::Failed).await?;
        }

        Ok(())
    }

    /// Handle the DestinationConfirmed status - queue settlement transactions
    ///
    /// Transitions to: [`BundleStatus::SettlementsQueued`]
    async fn on_destination_confirmed(
        &self,
        bundle: &mut BundleWithStatus,
    ) -> Result<(), InteropBundleError> {
        tracing::info!(bundle_id = ?bundle.bundle.id, "All transactions confirmed, processing settlements");

        // Build settlements
        let settlement_txs = self.settlement_processor.build_settlements(&bundle.bundle).await?;

        // Queue and send the settlement transactions
        let new_status = self
            .queue_and_send_bundle_transactions(
                bundle,
                InteropTransactionBatch::ExecuteSend(&settlement_txs),
            )
            .await?;

        bundle.bundle.settlement_txs = settlement_txs;
        bundle.status = new_status;

        tracing::info!(
            bundle_id = ?bundle.bundle.id,
            num_settlements = bundle.bundle.settlement_txs.len(),
            "Settlement transactions queued and sent"
        );

        Ok(())
    }

    /// Handle the RefundsScheduled status.
    ///
    /// Transitions to: stays in [`BundleStatus::RefundsScheduled`] (exits loop, waits for refund
    /// monitor to resume)
    async fn on_refunds_scheduled(
        &self,
        bundle: &mut BundleWithStatus,
    ) -> Result<(), InteropBundleError> {
        tracing::info!(bundle_id = ?bundle.bundle.id, "Refunds are scheduled, exiting processing loop");

        // The refund monitor service will pick this up when the refunds are ready
        // and transition it to RefundsReady status
        Err(InteropBundleError::RefundsNotReady)
    }

    /// Handle the RefundsReady status - build and send refund transactions
    ///
    /// Transitions to: [`BundleStatus::RefundsQueued`]
    async fn on_refunds_ready(
        &self,
        bundle: &mut BundleWithStatus,
    ) -> Result<(), InteropBundleError> {
        tracing::info!(bundle_id = ?bundle.bundle.id, "Processing ready refunds");

        // Build the refund transactions
        let escrow_details = self.refund_processor.get_confirmed_escrows(&bundle.bundle).await?;
        let refunds =
            self.refund_processor.build_missing_refunds(&bundle.bundle, &escrow_details).await?;

        // Queue and send transactions atomically
        let new_status = self
            .queue_and_send_bundle_transactions(
                bundle,
                InteropTransactionBatch::Refund(&refunds.new_refund_txs),
            )
            .await?;

        bundle.bundle.refund_txs = refunds.new_refund_txs;
        bundle.status = new_status;

        tracing::info!(
            bundle_id = ?bundle.bundle.id,
            new_tx_count = bundle.bundle.refund_txs.len(),
            "Built, queued, and sent refund transactions"
        );

        Ok(())
    }

    /// Handle the RefundsQueued status - monitor refund transactions and retry if needed
    ///
    /// Transitions to: [`BundleStatus::Failed`] when all refunds succeed
    async fn on_refunds_queued(
        &self,
        bundle: &mut BundleWithStatus,
    ) -> Result<(), InteropBundleError> {
        tracing::info!(bundle_id = ?bundle.bundle.id, "Monitoring refund transactions");
        let _failed_tx_ids =
            self.monitor_bundle_transactions(bundle.bundle.id, &bundle.bundle.refund_txs).await?;

        self.update_bundle_status(bundle, BundleStatus::Failed).await?;

        Ok(())
    }

    /// Handle the SettlementsQueued status - wait for settlement transactions
    ///
    /// Transitions to: [`BundleStatus::SettlementsProcessing`] OR [`BundleStatus::Failed`]
    async fn on_settlements_queued(
        &self,
        bundle: &mut BundleWithStatus,
    ) -> Result<(), InteropBundleError> {
        tracing::info!(bundle_id = ?bundle.bundle.id, "Monitoring settlement transactions");

        // Monitor settlement completion (transactions were already sent in queue_settlements)
        let failed_ids = self
            .monitor_bundle_transactions(bundle.bundle.id, &bundle.bundle.settlement_txs)
            .await?;

        // todo(joshieDo): right now we only have one settlement tx, so no need to handle the
        // settlement transactions that did succeed.
        if !failed_ids.is_empty() {
            tracing::error!(
                bundle_id = ?bundle.bundle.id,
                failed_count = failed_ids.len(),
                "Some settlement transactions failed, marking bundle as failed"
            );
            self.update_bundle_status(bundle, BundleStatus::Failed).await?;
        } else {
            tracing::info!(bundle_id = ?bundle.bundle.id, "All settlement transactions confirmed, transitioning to processing");
            self.update_bundle_status(bundle, BundleStatus::SettlementsProcessing).await?;
        }

        Ok(())
    }

    /// Handle the SettlementsProcessing status - perform settler-specific processing
    ///
    /// Transitions to: [`BundleStatus::SettlementCompletionQueued`].
    async fn on_settlements_processing(
        &self,
        bundle: &mut BundleWithStatus,
    ) -> Result<(), InteropBundleError> {
        tracing::info!(bundle_id = ?bundle.bundle.id, "Processing settler-specific verification");

        // Wait for verifications with timeout
        let timeout = self.interop_config.settler.wait_verification_timeout;
        let verification_result =
            self.settlement_processor.wait_for_verifications(&bundle.bundle, timeout).await?;

        // Check if there were any failures
        let verified_count = verification_result.verified_packets.len();
        let failed_count = verification_result.failed_packets.len();

        if failed_count > 0 {
            // Store failure details in the bundle
            bundle.bundle.failed_verifications =
                verification_result.failed_packets.into_iter().map(|(packet, _)| packet).collect();

            tracing::warn!(
                bundle_id = ?bundle.bundle.id,
                verified_count,
                failed_count,
                "Verification partially failed"
            );
        } else {
            tracing::info!(
                bundle_id = ?bundle.bundle.id,
                verified_count,
                "All verifications successful"
            );
        }

        // Build execute receive transactions for verified messages
        // Even if some failed, we proceed with the ones that succeeded
        let execute_receive_txs =
            self.settlement_processor.build_execute_receive_transactions(&bundle.bundle).await?;

        tracing::info!(
            bundle_id = ?bundle.bundle.id,
            tx_count = execute_receive_txs.len(),
            "Built execute receive transactions"
        );

        // Update status, queue and send transactions atomically
        let new_status = self
            .queue_and_send_bundle_transactions(
                bundle,
                InteropTransactionBatch::ExecuteReceive(&execute_receive_txs),
            )
            .await?;

        bundle.bundle.execute_receive_txs = execute_receive_txs;
        bundle.status = new_status;

        Ok(())
    }

    /// Handle the SettlementCompletionQueued status - monitor settlement completion transactions
    ///
    /// Transitions to: [`BundleStatus::Done`] OR [`BundleStatus::Failed`]
    async fn on_settlement_completion_queued(
        &self,
        bundle: &mut BundleWithStatus,
    ) -> Result<(), InteropBundleError> {
        tracing::info!(bundle_id = ?bundle.bundle.id, "Monitoring settlement completion transactions");

        let failed_tx_ids = self
            .monitor_bundle_transactions(bundle.bundle.id, &bundle.bundle.execute_receive_txs)
            .await?;

        let next_status = if !bundle.bundle.failed_verifications.is_empty()
            || !failed_tx_ids.is_empty()
        {
            tracing::warn!(
                bundle_id = ?bundle.bundle.id,
                failed_verifications = bundle.bundle.failed_verifications.len(),
                failed_receive_txs = failed_tx_ids.len(),
                "Bundle has verification failures, marking as failed"
            );
            BundleStatus::Failed
        } else {
            tracing::info!(bundle_id = ?bundle.bundle.id, "All settlements complete, marking bundle as done");
            BundleStatus::Done
        };

        self.update_bundle_status(bundle, next_status).await?;
        Ok(())
    }

    /// Handle the Done status - finalize the bundle
    ///
    /// Terminal state - moves bundle to finished_bundles table and exits
    async fn on_done(&self, bundle: &mut BundleWithStatus) -> Result<(), InteropBundleError> {
        tracing::info!(bundle_id = ?bundle.bundle.id, "Bundle completed successfully");

        // Move bundle to finished_bundles table
        self.storage.move_bundle_to_finished(bundle.bundle.id).await?;
        Ok(())
    }

    /// Handle the Failed status - finalize the failed bundle
    ///
    /// Terminal state - moves bundle to finished_bundles table and exits
    async fn on_failed(&self, bundle: &mut BundleWithStatus) -> Result<(), InteropBundleError> {
        tracing::error!(bundle_id = ?bundle.bundle.id, "Bundle is in failed state");

        // Move bundle to finished_bundles table
        self.storage.move_bundle_to_finished(bundle.bundle.id).await?;
        Ok(())
    }

    /// Send transactions that are already queued.
    async fn send_transactions(
        &self,
        transactions: &[RelayTransaction],
    ) -> Result<(), InteropBundleError> {
        try_join_all(transactions.iter().map(async |tx| {
            self.tx_service_handles
                .get(&tx.chain_id())
                .ok_or(InteropBundleError::NoTransactionService(tx.chain_id()))?
                .send_transaction_no_queue(tx.clone());
            Ok::<(), InteropBundleError>(())
        }))
        .await?;

        Ok(())
    }

    /// Watch intent transactions until they complete.
    async fn watch_intent_transactions(
        &self,
        txs: impl Iterator<Item = &RelayTransaction>,
    ) -> Result<
        Vec<(TxId, Result<TransactionReceipt, Arc<dyn TransactionFailureReason>>)>,
        InteropBundleError,
    > {
        try_join_all(txs.map(|tx| async move {
            let tx_service = self
                .tx_service_handles
                .get(&tx.chain_id())
                .ok_or(InteropBundleError::NoTransactionService(tx.chain_id()))?;

            // Convert to result based on status type
            let result = match tx_service.wait_for_tx(tx.id).await? {
                TransactionStatus::Confirmed(receipt) => {
                    tracing::debug!(tx_id = ?tx.id, "Transaction confirmed");
                    match IntentExecuted::try_from_receipt(&receipt) {
                        Some(event) if !event.has_error() => Ok(*receipt),
                        Some(event) => Err(Arc::new(InteropBundleError::IntentExecutionFailed(
                            event.err.to_string(),
                        )) as _),
                        None => Err(Arc::new(InteropBundleError::IntentEventNotFound) as _),
                    }
                }
                TransactionStatus::Failed(err) => {
                    tracing::warn!(tx_id = ?tx.id, "Transaction failed");
                    Err(err)
                }
                _ => unreachable!("wait_for_tx only returns final statuses"),
            };

            Ok((tx.id, result))
        }))
        .await
    }

    /// Process destination transactions for a bundle.
    ///
    /// Waits for all destination transactions to complete and unlocks the liquidity.
    async fn process_destination_transactions(
        &self,
        bundle: &InteropBundle,
    ) -> Result<(BundleStatus, HashMap<TxId, TransactionReceipt>), InteropBundleError> {
        // Wait for transactions queued by `queue_bundle_transactions
        let results = self.watch_intent_transactions(bundle.dst_txs.iter()).await?;

        // Collect receipts and check if any failed
        let mut receipts =
            HashMap::with_capacity_and_hasher(bundle.dst_txs.len(), Default::default());
        let mut any_failed = false;

        for (tx_id, result) in results {
            match result {
                Ok(receipt) => {
                    receipts.insert(tx_id, receipt);
                }
                Err(err) => {
                    tracing::error!(tx_id = ?tx_id, ?err, "Destination transaction failed");
                    any_failed = true;
                }
            }
        }

        let status = if any_failed {
            BundleStatus::DestinationFailures
        } else {
            BundleStatus::DestinationConfirmed
        };

        Ok((status, receipts))
    }

    /// Monitors transaction completion and returns the IDs of any failed transactions.
    ///
    /// # Arguments
    /// * `bundle_id` - The bundle ID for logging context
    /// * `transactions` - The transactions to monitor
    ///
    /// # Returns
    /// The IDs of any failed transactions.
    async fn monitor_bundle_transactions(
        &self,
        bundle_id: BundleId,
        transactions: &[RelayTransaction],
    ) -> Result<Vec<TxId>, InteropBundleError> {
        tracing::info!(
            bundle_id = ?bundle_id,
            num_transactions = transactions.len(),
            "Monitoring bundle transaction completion"
        );

        // Wait for all transactions to complete
        let results = try_join_all(transactions.iter().map(async |tx| {
            let tx_service = self
                .tx_service_handles
                .get(&tx.chain_id())
                .ok_or_else(|| InteropBundleError::NoTransactionService(tx.chain_id()))?;

            let status = tx_service.wait_for_tx(tx.id).await?;
            Ok::<_, InteropBundleError>((tx.id, status))
        }))
        .await?;

        // Process results and collect failed transaction IDs
        let failed_ids = results
            .into_iter()
            .filter_map(|(tx_id, status)| match status {
                TransactionStatus::Confirmed(_) => {
                    tracing::info!(tx_id = ?tx_id, "Bundle transaction confirmed");
                    None
                }
                TransactionStatus::Failed(e) => {
                    tracing::warn!(tx_id = ?tx_id, error = %e, "Bundle transaction failed");
                    Some(tx_id)
                }
                _ => unreachable!("wait_for_tx only returns finalized statuses"),
            })
            .collect();

        Ok(failed_ids)
    }

    /// Queues and sends a batch of transactions, updating the bundle's status.
    ///
    /// Also, this method handles all transaction types in the interop bundle lifecycle:
    /// - Source/Destination: Already in bundle, just queued and sent
    /// - Settlement types (ExecuteSend/ExecuteReceive/Refund): Appended to bundle, then queued and
    ///   sent
    async fn queue_and_send_bundle_transactions(
        &self,
        bundle: &BundleWithStatus,
        transaction_batch: InteropTransactionBatch<'_>,
    ) -> Result<BundleStatus, InteropBundleError> {
        // Extract transactions and determine next status using the type's methods
        let transactions = transaction_batch.transactions();
        let next_status = transaction_batch.next_status();

        // Validate state transition
        if !bundle.status.can_transition_to(&next_status) {
            return Err(InteropBundleError::InvalidStateTransition {
                from: bundle.status,
                to: next_status,
            });
        }

        // First validate we have all required transaction services
        self.validate_transaction_services(transactions)?;

        debug!(
            bundle_id = ?bundle.bundle.id,
            new_status = ?next_status,
            tx_count = transactions.len(),
            "Queueing and sending bundle transactions"
        );

        // todo(joshie): easy optimization can be to only write to disk the new data in a new
        // table/column
        let bundle_to_store = if transaction_batch.is_settlement() {
            let mut updated_bundle = bundle.bundle.clone();
            updated_bundle.append_transactions(&transaction_batch);
            Cow::Owned(updated_bundle)
        } else {
            // can use the bundle as-is for Source/Destination types
            Cow::Borrowed(&bundle.bundle)
        };

        self.storage
            .update_bundle_and_queue_transactions(&bundle_to_store, next_status, transactions)
            .await?;

        // Only now do we send to the transaction service.
        self.send_transactions(transactions).await?;

        debug!(
            bundle_id = ?bundle.bundle.id,
            tx_count = transactions.len(),
            "Successfully queued and sent bundle transactions"
        );

        Ok(next_status)
    }

    /// Validates that transaction services exist for all transactions in the list.
    ///
    /// # Arguments
    /// * `transactions` - The transactions to validate
    ///
    /// # Returns
    /// * `Ok(())` - If all required transaction services exist
    /// * `Err(InteropBundleError)` - If any required transaction service is missing
    fn validate_transaction_services(
        &self,
        transactions: &[RelayTransaction],
    ) -> Result<(), InteropBundleError> {
        for tx in transactions {
            if !self.tx_service_handles.contains_key(&tx.chain_id()) {
                error!(
                    chain_id = tx.chain_id(),
                    tx_id = ?tx.id,
                    "No transaction service found for chain"
                );
                return Err(InteropBundleError::NoTransactionService(tx.chain_id()));
            }
        }
        Ok(())
    }

    /// # Bundle State Machine
    ///
    /// ```text
    ///                              Init
    ///                               │
    ///                               ▼
    ///                        LiquidityLocked
    ///                               │
    ///                               ▼
    ///                          SourceQueued
    ///                          ╱         ╲
    ///                         ╱           ╲
    ///                        ▼             ▼
    ///                 SourceConfirmed   SourceFailures ─────────┐
    ///                        │                                  │
    ///                        ▼                                  │
    ///                 DestinationQueued                         │
    ///                    ╱         ╲                            │
    ///                   ╱           ╲                           │
    ///                  ▼             ▼                          │
    ///           DestConfirmed   DestinationFailures ────────────┤
    ///                  │                                        │
    ///                  ▼                                        │
    ///           SettlementsQueued ──────────────────────────┐   │
    ///                  │                                    │   │
    ///                  ▼                                    │   │
    ///         SettlementsProcessing                         │   │
    ///                  │                                    │   │
    ///                  ▼                                    │   │
    ///      SettlementCompletionQueued ──────────────────────┤   │
    ///                  │                                    │   │
    ///                  ▼                                    │   │
    ///                Done                                   │   │
    ///                                                       │   │
    ///                                                       │   ▼
    ///                                                       │  RefundsScheduled
    ///                                                       │   │
    ///                                                       │   ▼
    ///                                                       │  RefundsReady
    ///                                                       │   │
    ///                                                       │   ▼
    ///                                                       │  RefundsQueued
    ///                                                       │   │
    ///                                                       │   │
    ///                                                       ▼   ▼
    ///                                                       Failed
    ///                                               (Terminal State)
    /// ```
    #[instrument(skip(self, bundle), fields(bundle_id = %bundle.bundle.id))]
    async fn send_and_watch_bundle_with_status(
        &self,
        mut bundle: BundleWithStatus,
    ) -> Result<(), InteropBundleError> {
        loop {
            match bundle.status {
                BundleStatus::Init => self.on_init(&mut bundle).await?,
                BundleStatus::LiquidityLocked => self.on_liquidity_locked(&mut bundle).await?,
                BundleStatus::SourceQueued => self.on_source_queued(&mut bundle).await?,
                BundleStatus::SourceConfirmed => self.on_source_confirmed(&mut bundle).await?,
                BundleStatus::SourceFailures => self.on_source_failures(&mut bundle).await?,
                BundleStatus::DestinationQueued => self.on_destination_queued(&mut bundle).await?,
                BundleStatus::DestinationFailures => {
                    self.on_destination_failures(&mut bundle).await?
                }
                BundleStatus::DestinationConfirmed => {
                    self.on_destination_confirmed(&mut bundle).await?
                }
                BundleStatus::RefundsScheduled => self.on_refunds_scheduled(&mut bundle).await?,
                BundleStatus::RefundsReady => self.on_refunds_ready(&mut bundle).await?,
                BundleStatus::RefundsQueued => self.on_refunds_queued(&mut bundle).await?,
                BundleStatus::SettlementsQueued => self.on_settlements_queued(&mut bundle).await?,
                BundleStatus::SettlementsProcessing => {
                    self.on_settlements_processing(&mut bundle).await?
                }
                BundleStatus::SettlementCompletionQueued => {
                    self.on_settlement_completion_queued(&mut bundle).await?
                }
                BundleStatus::Done => {
                    self.on_done(&mut bundle).await?;
                    break;
                }
                BundleStatus::Failed => {
                    self.on_failed(&mut bundle).await?;
                    break;
                }
            }
        }
        Ok(())
    }
}

/// Service for handling cross-chain interop bundles.
#[derive(Debug)]
pub struct InteropService {
    inner: Arc<InteropServiceInner>,
    command_rx: mpsc::UnboundedReceiver<InteropServiceMessage>,
}

impl InteropService {
    /// Creates a new interop service.
    pub async fn new(
        tx_service_handles: HashMap<ChainId, TransactionServiceHandle>,
        liquidity_tracker: LiquidityTracker,
        interop_config: InteropConfig,
    ) -> eyre::Result<(Self, InteropServiceHandle)> {
        let (command_tx, command_rx) = mpsc::unbounded_channel();

        let storage = liquidity_tracker.storage().clone();
        let providers = liquidity_tracker.providers().clone();

        let settlement_processor = Arc::new(
            interop_config.settler.settlement_processor(storage.clone(), providers.clone())?,
        );

        let service = Self {
            inner: Arc::new(InteropServiceInner::new(
                tx_service_handles,
                liquidity_tracker.clone(),
                storage.clone(),
                providers,
                Arc::clone(&settlement_processor),
                interop_config.clone(),
            )),
            command_rx,
        };

        let handle = InteropServiceHandle {
            command_tx,
            storage: storage.clone(),
            liquidity_tracker,
            settlement_processor,
        };

        // Spawn the refund monitor service with configured interval
        RefundMonitorService::with_interval(
            storage.clone(),
            handle.clone(),
            interop_config.refund_check_interval,
        )
        .spawn();

        let pending_bundles = storage.get_pending_bundles().await?;
        for bundle in pending_bundles {
            tracing::info!(
                bundle_id = ?bundle.bundle.id,
                status = ?bundle.status,
                src_count = bundle.bundle.src_txs.len(),
                dst_count = bundle.bundle.dst_txs.len(),
                "Resume pending interop bundle from disk"
            );

            // RefundsScheduled bundles are processed by the refund monitor.
            if bundle.status.is_refunds_scheduled() {
                tracing::info!(
                    bundle_id = ?bundle.bundle.id,
                    status = ?bundle.status,
                    "Skipping bundle - managed by RefundMonitorService"
                );
                continue;
            }

            handle.send_bundle_with_status(bundle);
        }

        Ok((service, handle))
    }
}

impl Future for InteropService {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        while let Poll::Ready(Some(command)) = self.command_rx.poll_recv(cx) {
            match command {
                InteropServiceMessage::SendBundleWithStatus(bundle) => {
                    let bundle_id = bundle.bundle.id;
                    let inner = Arc::clone(&self.inner);
                    tokio::spawn(async move {
                        match inner.send_and_watch_bundle_with_status(*bundle).await {
                            Ok(()) => {}
                            Err(InteropBundleError::RefundsNotReady) => {
                                // This is expected - refunds will be handled by the refund monitor
                                tracing::debug!(bundle_id = %bundle_id, "Bundle processing paused - waiting for refund timestamp");
                            }
                            Err(e) => {
                                error!(bundle_id = %bundle_id, error = ?e, "Failed to process interop bundle");
                            }
                        }
                    });
                }
            }
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::InteropConfig,
        interop::{SettlementProcessor, Settler},
        storage::RelayStorage,
    };
    use alloy::{primitives::B256, providers::DynProvider};
    use async_trait::async_trait;
    use sqlx::PgPool;
    use std::time::Duration;

    async fn get_test_storage() -> RelayStorage {
        if let Ok(db_url) = std::env::var("DATABASE_URL") {
            // Use PostgreSQL if DATABASE_URL is set
            let pool = PgPool::connect(&db_url)
                .await
                .expect("Failed to connect to PostgreSQL with DATABASE_URL");

            // Run migrations
            sqlx::migrate!().run(&pool).await.expect("Failed to run migrations");

            RelayStorage::pg(pool)
        } else {
            // Use in-memory storage if DATABASE_URL is not set
            RelayStorage::in_memory()
        }
    }

    // Mock settler for tests
    #[derive(Debug)]
    struct MockSettler;

    #[async_trait]
    impl Settler for MockSettler {
        fn id(&self) -> SettlerId {
            SettlerId::Test
        }

        fn address(&self) -> Address {
            Address::default()
        }

        async fn build_execute_send_transaction(
            &self,
            _settlement_id: B256,
            _current_chain_id: u64,
            _source_chains: Vec<u64>,
            _orchestrator: Address,
        ) -> Result<Option<RelayTransaction>, crate::interop::SettlementError> {
            Ok(Some(RelayTransaction::new_internal(Address::default(), vec![], 0, 1_000_000)))
        }

        fn encode_settler_context(
            &self,
            _destination_chains: Vec<u64>,
        ) -> Result<alloy::primitives::Bytes, crate::interop::SettlementError> {
            Ok(alloy::primitives::Bytes::new())
        }

        async fn wait_for_verifications(
            &self,
            _bundle: &InteropBundle,
            _timeout: Duration,
        ) -> Result<crate::interop::settler::VerificationResult, crate::interop::SettlementError>
        {
            Ok(crate::interop::settler::VerificationResult {
                verified_packets: vec![],
                failed_packets: vec![],
            })
        }

        async fn build_execute_receive_transactions(
            &self,
            _bundle: &InteropBundle,
        ) -> Result<Vec<RelayTransaction>, crate::interop::SettlementError> {
            Ok(vec![])
        }
    }

    #[test]
    fn test_bundle_status_transitions() {
        use BundleStatus::*;

        // Valid transitions
        assert!(Init.can_transition_to(&LiquidityLocked));
        assert!(LiquidityLocked.can_transition_to(&SourceQueued));
        assert!(SourceQueued.can_transition_to(&SourceConfirmed));
        assert!(SourceQueued.can_transition_to(&SourceFailures));
        assert!(SourceConfirmed.can_transition_to(&DestinationQueued));
        assert!(SourceFailures.can_transition_to(&RefundsScheduled));
        assert!(SourceFailures.can_transition_to(&Failed));
        assert!(DestinationQueued.can_transition_to(&DestinationConfirmed));
        assert!(DestinationQueued.can_transition_to(&DestinationFailures));
        assert!(DestinationFailures.can_transition_to(&RefundsScheduled));
        assert!(DestinationFailures.can_transition_to(&Failed));
        assert!(DestinationConfirmed.can_transition_to(&SettlementsQueued));
        assert!(SettlementsQueued.can_transition_to(&SettlementsProcessing));
        assert!(SettlementsQueued.can_transition_to(&Failed));
        assert!(SettlementsProcessing.can_transition_to(&SettlementCompletionQueued));
        assert!(SettlementsProcessing.can_transition_to(&Done));
        assert!(SettlementCompletionQueued.can_transition_to(&Done));
        assert!(SettlementCompletionQueued.can_transition_to(&Failed));
        assert!(RefundsScheduled.can_transition_to(&RefundsReady));
        assert!(RefundsReady.can_transition_to(&RefundsQueued));
        assert!(RefundsQueued.can_transition_to(&Failed));

        // Invalid transitions
        assert!(!Init.can_transition_to(&SourceConfirmed));
        assert!(!Init.can_transition_to(&SourceQueued)); // Must go through LiquidityLocked
        assert!(!Init.can_transition_to(&Done));
        assert!(!LiquidityLocked.can_transition_to(&SourceConfirmed));
        assert!(!LiquidityLocked.can_transition_to(&DestinationQueued));
        assert!(!SourceQueued.can_transition_to(&DestinationQueued));
        assert!(!DestinationConfirmed.can_transition_to(&SourceQueued));
        assert!(!Done.can_transition_to(&Init));
        assert!(!Failed.can_transition_to(&Init));
        assert!(!RefundsQueued.can_transition_to(&RefundsScheduled));
    }

    #[test]
    fn test_interop_bundle_creation() {
        let bundle_id = BundleId::random();
        let settler_id = SettlerId::Test;
        let bundle = InteropBundle::new(bundle_id, settler_id);

        assert_eq!(bundle.id, bundle_id);
        assert_eq!(bundle.settler_id, settler_id);
        assert!(bundle.src_txs.is_empty());
        assert!(bundle.dst_txs.is_empty());
        assert!(bundle.asset_transfers.is_empty());
        assert!(bundle.refund_txs.is_empty());
        assert!(bundle.settlement_txs.is_empty());
        assert!(bundle.execute_receive_txs.is_empty());
    }

    #[test]
    fn test_settlement_state_transitions() {
        use BundleStatus::*;

        // Test settlement-specific transitions
        assert!(DestinationConfirmed.can_transition_to(&SettlementsQueued));
        assert!(SettlementsQueued.can_transition_to(&SettlementsProcessing));
        assert!(SettlementsQueued.can_transition_to(&Failed));
        assert!(SettlementsProcessing.can_transition_to(&SettlementCompletionQueued));
        assert!(SettlementsProcessing.can_transition_to(&Done));
        assert!(SettlementCompletionQueued.can_transition_to(&Done));
        assert!(SettlementCompletionQueued.can_transition_to(&Failed));

        // Invalid transitions
        assert!(!SettlementsQueued.can_transition_to(&DestinationConfirmed));
        assert!(!SettlementsProcessing.can_transition_to(&SettlementsQueued));
        assert!(!SettlementCompletionQueued.can_transition_to(&SettlementsProcessing));
    }

    #[tokio::test]
    async fn test_bundle_persistence_and_recovery() {
        let storage = get_test_storage().await;
        let bundle_id = BundleId::random();
        let bundle = InteropBundle::new(bundle_id, SettlerId::Test);

        // Store bundle with Init status
        storage.store_pending_bundle(&bundle, BundleStatus::Init).await.unwrap();

        // Retrieve bundle
        let retrieved = storage.get_pending_bundle(bundle_id).await.unwrap();
        assert!(retrieved.is_some());

        let bundle_with_status = retrieved.unwrap();
        assert_eq!(bundle_with_status.bundle.id, bundle_id);
        assert_eq!(bundle_with_status.status, BundleStatus::Init);

        // Update status to LiquidityLocked first
        storage
            .update_pending_bundle_status(bundle_id, BundleStatus::LiquidityLocked)
            .await
            .unwrap();

        // Verify status updated
        let updated = storage.get_pending_bundle(bundle_id).await.unwrap().unwrap();
        assert_eq!(updated.status, BundleStatus::LiquidityLocked);

        // Update to SourceQueued
        storage.update_pending_bundle_status(bundle_id, BundleStatus::SourceQueued).await.unwrap();

        // Verify status updated
        let updated = storage.get_pending_bundle(bundle_id).await.unwrap().unwrap();
        assert_eq!(updated.status, BundleStatus::SourceQueued);

        // Move to finished
        storage.update_pending_bundle_status(bundle_id, BundleStatus::Done).await.unwrap();
        storage.move_bundle_to_finished(bundle_id).await.unwrap();

        // Verify no longer in pending
        assert!(storage.get_pending_bundle(bundle_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_invalid_state_transition_error() {
        let storage = get_test_storage().await;
        let providers: HashMap<ChainId, DynProvider> = HashMap::default();
        let tx_handles: HashMap<ChainId, TransactionServiceHandle> = HashMap::default();
        let funder = Address::default();

        let settlement_processor = SettlementProcessor::new(Box::new(MockSettler));

        let inner = InteropServiceInner::new(
            tx_handles,
            LiquidityTracker::new(providers.clone(), funder, storage.clone()),
            storage,
            providers,
            Arc::new(settlement_processor),
            InteropConfig::default(),
        );

        let bundle_id = BundleId::random();
        let bundle = InteropBundle::new(bundle_id, SettlerId::Test);
        let mut bundle_with_status = BundleWithStatus {
            bundle,
            status: BundleStatus::Done, // Terminal state
        };

        // Try invalid transition from Done to SourceQueued
        let result =
            inner.update_bundle_status(&mut bundle_with_status, BundleStatus::SourceQueued).await;

        assert!(matches!(
            result,
            Err(InteropBundleError::InvalidStateTransition {
                from: BundleStatus::Done,
                to: BundleStatus::SourceQueued
            })
        ));
    }
}
