use super::{
    RelayTransaction, TransactionFailureReason, TransactionServiceHandle, TransactionStatus, TxId,
};
use crate::{
    error::StorageError,
    liquidity::{LiquidityTracker, LiquidityTrackerError},
    storage::{RelayStorage, StorageApi},
    types::{InteropTxType, OrchestratorContract::IntentExecuted, rpc::BundleId},
};
use alloy::{
    primitives::{Address, ChainId, U256, map::HashMap},
    providers::{DynProvider, MulticallError},
    rpc::types::TransactionReceipt,
};
use futures_util::future::try_join_all;
use serde::{Deserialize, Serialize};
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::sync::mpsc;
use tracing::{error, instrument};

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
    /// Source chain transactions
    pub src_txs: Vec<RelayTransaction>,
    /// Destination chain transactions
    pub dst_txs: Vec<RelayTransaction>,
    /// Pre-calculated asset transfers for liquidity tracking
    pub asset_transfers: Vec<AssetTransfer>,
}

impl InteropBundle {
    /// Creates a new empty interop bundle with the given ID
    pub fn new(id: BundleId) -> Self {
        Self { id, src_txs: Vec::new(), dst_txs: Vec::new(), asset_transfers: Vec::new() }
    }

    /// Appends a source transaction to the bundle
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
    WaitForTransaction(#[from] crate::transactions::TransactionServiceError),
    /// Intent execution failed with an error.
    #[error("intent execution failed: {0}")]
    IntentExecutionFailed(String),
    /// Intent executed event not found in receipt.
    #[error("IntentExecuted event not found in receipt")]
    IntentEventNotFound,
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
    /// Next: [`Self::RefundsQueued`] OR [`Self::Failed`]
    SourceFailures,
    /// Destination transactions are queued
    ///
    /// Next: [`Self::DestinationConfirmed`] OR [`Self::DestinationFailures`]
    DestinationQueued,
    /// Destination transactions have failures
    ///
    /// Next: [`Self::RefundsQueued`] OR [`Self::Failed`]
    DestinationFailures,
    /// Destination transactions are confirmed
    ///
    /// Next: [`Self::WithdrawalsQueued`]
    DestinationConfirmed,
    /// Refunds are queued to be processed
    ///
    /// Next: [`Self::Failed`]
    RefundsQueued,
    /// Withdrawals are queued to be processed
    ///
    /// Next: [`Self::Done`]
    WithdrawalsQueued,
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
                | (SourceFailures, RefundsQueued)
                | (SourceFailures, Failed)
                | (DestinationQueued, DestinationConfirmed)
                | (DestinationQueued, DestinationFailures)
                | (DestinationFailures, RefundsQueued)
                | (DestinationFailures, Failed)
                | (DestinationConfirmed, WithdrawalsQueued)
                | (RefundsQueued, Failed)
                | (WithdrawalsQueued, Done)
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
}

/// Internal state of the interop service.
#[derive(Debug)]
struct InteropServiceInner {
    tx_service_handles: HashMap<ChainId, TransactionServiceHandle>,
    liquidity_tracker: LiquidityTracker,
    storage: RelayStorage,
}

impl InteropServiceInner {
    /// Creates a new interop service inner state.
    fn new(
        tx_service_handles: HashMap<ChainId, TransactionServiceHandle>,
        liquidity_tracker: LiquidityTracker,
        storage: RelayStorage,
    ) -> Self {
        Self { tx_service_handles, liquidity_tracker, storage }
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

    /// Helper to queue transactions and update bundle status atomically
    async fn queue_transactions_and_update_status(
        &self,
        bundle: &mut BundleWithStatus,
        new_status: BundleStatus,
        tx_type: InteropTxType,
    ) -> Result<(), InteropBundleError> {
        // Validate state transition
        if !bundle.status.can_transition_to(&new_status) {
            return Err(InteropBundleError::InvalidStateTransition {
                from: bundle.status,
                to: new_status,
            });
        }

        self.storage.queue_bundle_transactions(&bundle.bundle, new_status, tx_type).await?;
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

        // Update status and queue source transactions atomically
        self.queue_transactions_and_update_status(
            bundle,
            BundleStatus::SourceQueued,
            InteropTxType::Source,
        )
        .await?;

        // Send the transactions
        self.send_transactions(&bundle.bundle.src_txs).await?;

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

        // Process source transactions (waits for completion)
        let new_status = match self.process_source_transactions(&bundle.bundle).await {
            Ok(()) => {
                // Update status to source confirmed
                BundleStatus::SourceConfirmed
            }
            Err(e) => {
                // Update status to source failures
                tracing::error!(bundle_id = ?bundle.bundle.id, error = ?e, "Source transactions failed");
                BundleStatus::SourceFailures
            }
        };

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
        tracing::info!(bundle_id = ?bundle.bundle.id, "Processing destination transactions");

        // Update status and queue destination transactions atomically
        self.queue_transactions_and_update_status(
            bundle,
            BundleStatus::DestinationQueued,
            InteropTxType::Destination,
        )
        .await?;

        // Send the transactions
        self.send_transactions(&bundle.bundle.dst_txs).await?;

        Ok(())
    }

    /// Handle bundles with source failures
    ///
    /// Transitions to: [`BundleStatus::RefundsQueued`] OR [`BundleStatus::Failed`] (TODO: implement
    /// logic)
    async fn on_source_failures(
        &self,
        bundle: &mut BundleWithStatus,
    ) -> Result<(), InteropBundleError> {
        tracing::warn!(
            bundle_id = ?bundle.bundle.id,
            "Handling source failures - TODO: implement retry logic or manual intervention"
        );
        // TODO: Issue refunds if any of the sources transactions passed.
        self.update_bundle_status(bundle, BundleStatus::Failed).await?;
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

        Ok(())
    }

    /// Handle bundles with destination failures
    ///
    /// Transitions to: [`BundleStatus::RefundsQueued`] OR [`BundleStatus::Failed`] (TODO: implement
    /// logic)
    async fn on_destination_failures(
        &self,
        bundle: &mut BundleWithStatus,
    ) -> Result<(), InteropBundleError> {
        tracing::warn!(
            bundle_id = ?bundle.bundle.id,
            "Handling destination failures - TODO: implement retry logic or refund mechanism"
        );

        // TODO: update bundle to RefundsQueued and process Refunds
        self.update_bundle_status(bundle, BundleStatus::Failed).await?;

        Ok(())
    }

    /// Handle the DestinationConfirmed status - prepare for withdrawals
    ///
    /// Transitions to: [`BundleStatus::WithdrawalsQueued`]
    async fn on_destination_confirmed(
        &self,
        bundle: &mut BundleWithStatus,
    ) -> Result<(), InteropBundleError> {
        tracing::info!(bundle_id = ?bundle.bundle.id, "All transactions confirmed, processing withdrawals");
        // TODO: Queue withdrawal transactions
        // For now, transition to WithdrawalsQueued state
        self.update_bundle_status(bundle, BundleStatus::WithdrawalsQueued).await?;
        Ok(())
    }

    /// Handle the RefundsQueued status - process refunds
    ///
    /// Transitions to: [`BundleStatus::Failed`]
    async fn on_refunds_queued(
        &self,
        bundle: &mut BundleWithStatus,
    ) -> Result<(), InteropBundleError> {
        tracing::info!(bundle_id = ?bundle.bundle.id, "Processing refunds");

        // TODO: Implement refund processing logic
        // - Check if refunds are confirmed
        // - If confirmed, transition to Failed or other
        self.update_bundle_status(bundle, BundleStatus::Failed).await?;
        Ok(())
    }

    /// Handle the WithdrawalsQueued status - process withdrawals
    ///
    /// Transitions to: [`BundleStatus::Done`]
    async fn on_withdrawals_queued(
        &self,
        bundle: &mut BundleWithStatus,
    ) -> Result<(), InteropBundleError> {
        tracing::info!(bundle_id = ?bundle.bundle.id, "Processing withdrawals");

        // TODO: Implement withdrawal processing logic

        self.update_bundle_status(bundle, BundleStatus::Done).await?;
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
        for tx in transactions {
            self.tx_service_handles
                .get(&tx.chain_id())
                .ok_or(InteropBundleError::NoTransactionService(tx.chain_id()))?
                .send_transaction_no_queue(tx.clone());
        }

        Ok(())
    }

    /// Watch transactions until they complete.
    async fn watch_transactions(
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

    /// Process source transactions for a bundle.
    ///
    /// Waits for all source transactions to complete.
    async fn process_source_transactions(
        &self,
        bundle: &InteropBundle,
    ) -> Result<(), InteropBundleError> {
        // Wait for transactions queued by `queue_bundle_transactions`
        let results = self.watch_transactions(bundle.src_txs.iter()).await?;

        // Check if any failed
        for (tx_id, result) in results {
            if let Err(err) = result {
                tracing::error!(tx_id = ?tx_id, "Source transaction failed");
                return Err(InteropBundleError::TransactionError(err));
            }
        }

        Ok(())
    }

    /// Process destination transactions for a bundle.
    ///
    /// Waits for all destination transactions to complete and unlocks the liquidity.
    async fn process_destination_transactions(
        &self,
        bundle: &InteropBundle,
    ) -> Result<(BundleStatus, HashMap<TxId, TransactionReceipt>), InteropBundleError> {
        // Wait for transactions queued by `queue_bundle_transactions
        let results = self.watch_transactions(bundle.dst_txs.iter()).await?;

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
    ///                 SourceConfirmed   SourceFailures ──┐
    ///                        │                           │
    ///                        ▼                           │
    ///                 DestinationQueued                  │
    ///                    ╱         ╲                     │
    ///                   ╱           ╲                    │
    ///                  ▼             ▼                   │
    ///           DestConfirmed   DestinationFailures ─────┤
    ///                  │                                 │
    ///                  ▼                                 │
    ///           WithdrawalsQueued                        │
    ///                  │                                 │
    ///                  │                                 ▼
    ///                  │                           RefundsQueued
    ///                  │                                 │
    ///                  ▼                                 ▼
    ///                 Done                            Failed
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
                BundleStatus::RefundsQueued => self.on_refunds_queued(&mut bundle).await?,
                BundleStatus::WithdrawalsQueued => self.on_withdrawals_queued(&mut bundle).await?,
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
        providers: HashMap<ChainId, DynProvider>,
        tx_service_handles: HashMap<ChainId, TransactionServiceHandle>,
        funder_address: Address,
        storage: RelayStorage,
    ) -> eyre::Result<(Self, InteropServiceHandle)> {
        let (command_tx, command_rx) = mpsc::unbounded_channel();

        let liquidity_tracker = LiquidityTracker::new(providers, funder_address, storage.clone());
        let pending_bundles = storage.get_pending_bundles().await?;

        let service = Self {
            inner: Arc::new(InteropServiceInner::new(
                tx_service_handles,
                liquidity_tracker.clone(),
                storage.clone(),
            )),
            command_rx,
        };

        let handle = InteropServiceHandle { command_tx, storage, liquidity_tracker };

        for bundle in pending_bundles {
            tracing::info!(
                bundle_id = ?bundle.bundle.id,
                status = ?bundle.status,
                src_count = bundle.bundle.src_txs.len(),
                dst_count = bundle.bundle.dst_txs.len(),
                "Resume pending interop bundle from disk"
            );

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
                        if let Err(e) = inner.send_and_watch_bundle_with_status(*bundle).await {
                            error!(bundle_id = %bundle_id, error = ?e, "Failed to process interop bundle");
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
    use crate::storage::RelayStorage;
    use sqlx::PgPool;

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

    #[test]
    fn test_bundle_status_transitions() {
        use BundleStatus::*;

        // Valid transitions
        assert!(Init.can_transition_to(&LiquidityLocked));
        assert!(LiquidityLocked.can_transition_to(&SourceQueued));
        assert!(SourceQueued.can_transition_to(&SourceConfirmed));
        assert!(SourceQueued.can_transition_to(&SourceFailures));
        assert!(SourceConfirmed.can_transition_to(&DestinationQueued));
        assert!(SourceFailures.can_transition_to(&RefundsQueued));
        assert!(SourceFailures.can_transition_to(&Failed));
        assert!(DestinationQueued.can_transition_to(&DestinationConfirmed));
        assert!(DestinationQueued.can_transition_to(&DestinationFailures));
        assert!(DestinationFailures.can_transition_to(&RefundsQueued));
        assert!(DestinationFailures.can_transition_to(&Failed));
        assert!(DestinationConfirmed.can_transition_to(&WithdrawalsQueued));
        assert!(RefundsQueued.can_transition_to(&Failed));
        assert!(WithdrawalsQueued.can_transition_to(&Done));

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
    }

    #[test]
    fn test_interop_bundle_creation() {
        let bundle_id = BundleId::random();
        let bundle = InteropBundle::new(bundle_id);

        assert_eq!(bundle.id, bundle_id);
        assert!(bundle.src_txs.is_empty());
        assert!(bundle.dst_txs.is_empty());
        assert!(bundle.asset_transfers.is_empty());
    }

    #[tokio::test]
    async fn test_bundle_persistence_and_recovery() {
        let storage = get_test_storage().await;
        let bundle_id = BundleId::random();
        let bundle = InteropBundle::new(bundle_id);

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

        let inner = InteropServiceInner::new(
            tx_handles,
            LiquidityTracker::new(providers, funder, storage.clone()),
            storage,
        );

        let bundle_id = BundleId::random();
        let bundle = InteropBundle::new(bundle_id);
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
