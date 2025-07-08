use super::{
    RelayTransaction, TransactionFailureReason, TransactionServiceError, TransactionServiceHandle,
    TransactionStatus, TxId,
};
use crate::{
    config::InteropConfig, error::StorageError, interop::{RefundMonitorService, RefundProcessor, RefundProcessorError}, storage::{RelayStorage, StorageApi}, types::{rpc::BundleId, InteropTxType, OrchestratorContract::IntentExecuted, IERC20}
};
use alloy::{
    primitives::{Address, BlockNumber, ChainId, U256, map::HashMap},
    providers::{DynProvider, MulticallError, Provider},
    rpc::types::TransactionReceipt,
};
use futures_util::future::{TryJoinAll, try_join_all};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::{Mutex, mpsc};
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
    /// Refund transactions (populated when src_txs fail)
    ///
    /// Only successful refund transactions are kept in the bundle.
    pub refund_txs: Vec<RelayTransaction>,
}

impl InteropBundle {
    /// Creates a new empty interop bundle with the given ID
    pub fn new(id: BundleId) -> Self {
        Self {
            id,
            src_txs: Vec::new(),
            dst_txs: Vec::new(),
            asset_transfers: Vec::new(),
            refund_txs: Vec::new(),
        }
    }

    /// Returns an iterator over the transactions of the specified type
    pub fn transactions(&self, tx_type: InteropTxType) -> impl Iterator<Item = &RelayTransaction> {
        match tx_type {
            InteropTxType::Source => self.src_txs.iter(),
            InteropTxType::Destination => self.dst_txs.iter(),
            InteropTxType::Refund => self.refund_txs.iter(),
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
                });
            }
        }

        self.dst_txs.push(tx);
    }
}

/// Bundle with its current status
#[derive(Debug, Clone)]
pub struct BundleWithStatus {
    /// The interop bundle containing transaction data
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
    /// Invalid state transition
    #[error("invalid state transition from {from:?} to {to:?}")]
    InvalidStateTransition { from: BundleStatus, to: BundleStatus },
    /// Not enough liquidity.
    #[error("don't have enough liquidity for the bundle")]
    NotEnoughLiquidity,
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
}

/// Status of a pending interop bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "bundle_status", rename_all = "snake_case")]
pub enum BundleStatus {
    /// Initial state before any processing
    ///
    /// Next: [`Self::SourceQueued`]
    Init,
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
    /// Next: [`Self::SettlementsConfirmed`] OR [`Self::Failed`]
    SettlementsQueued,
    /// Settlement transactions are confirmed
    ///
    /// Next: [`Self::Done`]
    SettlementsConfirmed,
    /// Refunds are scheduled for delayed execution
    ///
    /// Next: [`Self::RefundsReady`] OR stays in `RefundsScheduled`
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
            (Init, SourceQueued)
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
                | (SettlementsQueued, SettlementsConfirmed)
                | (SettlementsQueued, Failed)
                | (SettlementsConfirmed, Done)
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

/// Input for [`LiquidityTrackerInner::try_lock_liquidity`].
#[derive(Debug)]
struct LockLiquidityInput {
    /// Current balance of the asset fetched from provider.
    current_balance: U256,
    /// Block number at which the balance was fetched.
    balance_at: BlockNumber,
    /// Amount of the asset we are trying to lock.
    lock_amount: U256,
}

/// An address on a specific chain.
pub type ChainAddress = (ChainId, Address);

/// Tracks liquidity of relay for interop bundles.
#[derive(Debug, Default)]
struct LiquidityTrackerInner {
    /// Assets that are about to be pulled from us, indexed by chain and asset address.
    ///
    /// Those correspond to pending cross-chain intents that are not yet confirmed.
    locked_liquidity: HashMap<ChainAddress, U256>,
    /// Liquidity amounts that are unlocked at certain block numbers.
    ///
    /// Those correspond to blocks when we've sent funds to users.
    pending_unlocks: HashMap<ChainAddress, BTreeMap<BlockNumber, U256>>,
}

impl LiquidityTrackerInner {
    /// Does a pessimistic estimate of our balance in the given asset, subtracting all of the locked
    /// balances and adding all of the unlocked ones.
    fn available_balance(&self, asset: ChainAddress, input: &LockLiquidityInput) -> U256 {
        let locked = self.locked_liquidity.get(&asset).copied().unwrap_or_default();
        let unlocked = self
            .pending_unlocks
            .get(&asset)
            .map(|unlocks| {
                unlocks.range(..=input.balance_at).map(|(_, amount)| *amount).sum::<U256>()
            })
            .unwrap_or_default();

        input.current_balance.saturating_add(unlocked).saturating_sub(locked)
    }

    /// Attempts to lock liquidity by firstly making sure that we have enough funds for it.
    async fn try_lock_liquidity(
        &mut self,
        assets: HashMap<ChainAddress, LockLiquidityInput>,
    ) -> Result<(), InteropBundleError> {
        // Make sure that we have enough funds for all transfers
        if assets
            .iter()
            .any(|(asset, input)| input.lock_amount > self.available_balance(*asset, input))
        {
            return Err(InteropBundleError::NotEnoughLiquidity);
        }

        // Lock liquidity
        for (asset, input) in assets {
            *self.locked_liquidity.entry(asset).or_default() += input.lock_amount;
        }

        Ok(())
    }

    /// Unlocks liquidity by adding it to the pending unlocks mapping. This should be called once
    /// bundle is confirmed.
    fn unlock_liquidity(
        &mut self,
        chain_id: ChainId,
        asset: Address,
        amount: U256,
        at: BlockNumber,
    ) {
        *self.pending_unlocks.entry((chain_id, asset)).or_default().entry(at).or_default() +=
            amount;
    }
}

/// Wrapper around [`LiquidityTrackerInner`] that is used to track liquidity.
#[derive(Debug, Default)]
struct LiquidityTracker {
    inner: Arc<Mutex<LiquidityTrackerInner>>,
    funder_address: Address,
    providers: HashMap<ChainId, DynProvider>,
}

impl LiquidityTracker {
    /// Creates a new liquidity tracker.
    pub fn new(providers: HashMap<ChainId, DynProvider>, funder_address: Address) -> Self {
        let inner = Arc::new(Mutex::new(Default::default()));
        let this = Self { inner: inner.clone(), providers: providers.clone(), funder_address };

        // Spawn a task that periodically cleans up the pending unlocks for older blocks.
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;

                let result = providers
                    .iter()
                    .map(async |(chain, provider)| {
                        let latest_block = provider.get_block_number().await?;
                        let mut lock = inner.lock().await;
                        let LiquidityTrackerInner { locked_liquidity, pending_unlocks } =
                            &mut *lock;
                        for (asset, unlocks) in pending_unlocks {
                            if asset.0 == *chain {
                                // Keep 10 blocks of pending unlocks
                                let to_keep = unlocks.split_off(&latest_block.saturating_sub(10));
                                let to_remove = core::mem::replace(unlocks, to_keep);

                                // Remove everything else from the locked mapping
                                for (_, unlock) in to_remove {
                                    locked_liquidity.entry(*asset).and_modify(|amount| {
                                        *amount = amount.saturating_sub(unlock);
                                    });
                                }
                            }
                        }
                        eyre::Ok(())
                    })
                    .collect::<TryJoinAll<_>>()
                    .await;

                if let Err(e) = result {
                    error!("liquidity tracker task failed: {:?}", e);
                }
            }
        });

        this
    }

    /// Locks liquidity for an interop bundle.
    pub async fn try_lock_liquidity(
        &self,
        assets: impl IntoIterator<Item = AssetTransfer>,
    ) -> Result<(), InteropBundleError> {
        // Deduplicate assets by chain and asset address
        let inputs: HashMap<_, U256> = assets
            .into_iter()
            .map(|transfer| ((transfer.chain_id, transfer.asset_address), transfer.amount))
            .fold(HashMap::default(), |mut map, (k, v)| {
                *map.entry(k).or_default() += v;
                map
            });

        // Construct inputs for liquidity tracker by fetching balances
        let inputs = inputs
            .into_iter()
            .map(async |((chain, asset), amount)| {
                let provider = &self.providers[&chain];
                let (balance, block_number) = if !asset.is_zero() {
                    let (balance, block_number) = provider
                        .multicall()
                        .add(IERC20::new(asset, provider).balanceOf(self.funder_address))
                        .get_block_number()
                        .aggregate()
                        .await?;
                    (balance, block_number.to::<u64>())
                } else {
                    let block_number = provider.get_block_number().await?;
                    let balance = provider
                        .get_balance(self.funder_address)
                        .block_id(block_number.into())
                        .await?;
                    (balance, block_number)
                };

                Ok::<_, MulticallError>((
                    (chain, asset),
                    LockLiquidityInput {
                        current_balance: balance,
                        balance_at: block_number,
                        lock_amount: amount,
                    },
                ))
            })
            .collect::<TryJoinAll<_>>()
            .await?
            .into_iter()
            .collect();

        self.inner.lock().await.try_lock_liquidity(inputs).await?;

        Ok(())
    }

    /// Unlocks liquidity from an interop bundle.
    pub async fn unlock_liquidity(
        &self,
        chain_id: ChainId,
        asset: Address,
        amount: U256,
        at: BlockNumber,
    ) {
        self.inner.lock().await.unlock_liquidity(chain_id, asset, amount, at);
    }
}

/// Handle to communicate with the [`InteropService`].
#[derive(Debug, Clone)]
pub struct InteropServiceHandle {
    command_tx: mpsc::UnboundedSender<InteropServiceMessage>,
    storage: RelayStorage,
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
}

/// Internal state of the interop service.
#[derive(Debug)]
struct InteropServiceInner {
    tx_service_handles: HashMap<ChainId, TransactionServiceHandle>,
    liquidity_tracker: LiquidityTracker,
    storage: RelayStorage,
    refund_processor: RefundProcessor,
}

impl InteropServiceInner {
    /// Creates a new interop service inner state.
    fn new(
        tx_service_handles: HashMap<ChainId, TransactionServiceHandle>,
        liquidity_tracker: LiquidityTracker,
        storage: RelayStorage,
        providers: HashMap<ChainId, DynProvider>,
    ) -> Self {
        let refund_processor =
            RefundProcessor::new(storage.clone(), tx_service_handles.clone(), providers);
        Self { tx_service_handles, liquidity_tracker, storage, refund_processor }
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

    /// Handle the Init status - check liquidity and queue source transactions
    ///
    /// Transitions to: [`BundleStatus::SourceQueued`]
    async fn on_init(&self, bundle: &mut BundleWithStatus) -> Result<(), InteropBundleError> {
        tracing::info!(
            bundle_id = ?bundle.bundle.id,
            src_count = bundle.bundle.src_txs.len(),
            dst_count = bundle.bundle.dst_txs.len(),
            "Initializing bundle"
        );

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

        // Wait for all source transactions to complete
        let results = self.watch_transactions(bundle.bundle.src_txs.iter()).await?;

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
        self.refund_processor.schedule_refunds(bundle).await?;

        // Check if refunds were scheduled by examining the bundle status
        if !bundle.status.is_refunds_scheduled() {
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

        // Process destination transactions (waits for completion)
        let new_status = match self.process_destination_transactions(&bundle.bundle).await {
            Ok(()) => {
                // Update status to destination confirmed
                BundleStatus::DestinationConfirmed
            }
            Err(e) => {
                // Update status to destination failures
                tracing::error!(bundle_id = ?bundle.bundle.id, error = ?e, "Destination transactions failed");
                BundleStatus::DestinationFailures
            }
        };

        self.update_bundle_status(bundle, new_status).await?;
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

        self.refund_processor.schedule_refunds(bundle).await?;

        // Check if refunds were scheduled by examining the bundle status
        if !bundle.status.is_refunds_scheduled() {
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
        tracing::info!(bundle_id = ?bundle.bundle.id, "All transactions confirmed, processing withdrawals");
        // TODO: Queue settlement transactions
        // For now, transition to SettlementsQueued state
        self.update_bundle_status(bundle, BundleStatus::SettlementsQueued).await?;
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

        self.refund_processor.queue_refunds(bundle).await?;

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

        // This will keep retrying until all refunds complete or error
        self.refund_processor.monitor_and_process_refunds(bundle).await?;

        tracing::info!(
            bundle_id = ?bundle.bundle.id,
            refund_tx_count = bundle.bundle.refund_txs.len(),
            "All refund transactions succeeded, keeping successful transactions and marking bundle as failed"
        );

        self.update_bundle_status(bundle, BundleStatus::Failed).await?;

        Ok(())
    }

    /// Handle the SettlementsQueued status - wait for settlement transactions
    ///
    /// Transitions to: [`BundleStatus::SettlementsConfirmed`] OR [`BundleStatus::Failed`]
    async fn on_settlements_queued(
        &self,
        bundle: &mut BundleWithStatus,
    ) -> Result<(), InteropBundleError> {
        tracing::info!(bundle_id = ?bundle.bundle.id, "Processing settlement transactions");

        // TODO: Wait for settlement transactions to complete
        // For now, assume they complete successfully
        self.update_bundle_status(bundle, BundleStatus::SettlementsConfirmed).await?;
        Ok(())
    }

    /// Handle the SettlementsConfirmed status - finalize the bundle
    ///
    /// Transitions to: [`BundleStatus::Done`]
    async fn on_settlements_confirmed(
        &self,
        bundle: &mut BundleWithStatus,
    ) -> Result<(), InteropBundleError> {
        tracing::info!(bundle_id = ?bundle.bundle.id, "Settlements confirmed, marking bundle as done");

        // Transition directly to done
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

    /// Process destination transactions for a bundle.
    ///
    /// Waits for all destination transactions to complete and unlocks the liquidity.
    async fn process_destination_transactions(
        &self,
        bundle: &InteropBundle,
    ) -> Result<(), InteropBundleError> {
        let mut maybe_err = Ok(());

        // Wait for transactions queued by `queue_bundle_transactions
        let results = self.watch_transactions(bundle.dst_txs.iter()).await?;

        // Collect receipts and check if any failed
        let mut receipts = HashMap::with_capacity(bundle.dst_txs.len());
        for (tx_id, result) in results {
            match result {
                Ok(receipt) => {
                    receipts.insert(tx_id, receipt);
                }
                Err(err) => {
                    tracing::error!(tx_id = ?tx_id, ?err, "Destination transaction failed");
                    maybe_err = Err(InteropBundleError::TransactionError(err));
                }
            }
        }

        for (transfer, tx) in bundle.asset_transfers.iter().zip(&bundle.dst_txs) {
            let block = receipts.get(&tx.id).and_then(|r| r.block_number).unwrap_or_default();

            self.liquidity_tracker
                .unlock_liquidity(transfer.chain_id, transfer.asset_address, transfer.amount, block)
                .await;
        }

        maybe_err
    }

    /// # Bundle State Machine
    ///
    /// ```text
    ///                              Init
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
    ///           SettlementsQueued                        │
    ///                  │                                 │
    ///                  ▼                                 │
    ///         SettlementsConfirmed                       │
    ///                  │                                 │
    ///                  │                                 ▼
    ///                  │                           RefundsScheduled
    ///                  │                                 │
    ///                  │                                 ▼
    ///                  │                           RefundsReady
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
        // Lock liquidity before processing the bundle (skip if already has processed the
        // destination transactions)
        if !bundle.status.is_destination_failures() && !bundle.status.is_destination_confirmed() {
            self.liquidity_tracker
                .try_lock_liquidity(bundle.bundle.asset_transfers.clone())
                .await?;
        }

        loop {
            match bundle.status {
                BundleStatus::Init => self.on_init(&mut bundle).await?,
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
                BundleStatus::SettlementsConfirmed => {
                    self.on_settlements_confirmed(&mut bundle).await?
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
        providers: HashMap<ChainId, DynProvider>,
        tx_service_handles: HashMap<ChainId, TransactionServiceHandle>,
        funder_address: Address,
        interop_config: InteropConfig,
        storage: RelayStorage,
    ) -> eyre::Result<(Self, InteropServiceHandle)> {
        let (command_tx, command_rx) = mpsc::unbounded_channel();

        let liquidity_tracker = LiquidityTracker::new(providers.clone(), funder_address);
        let pending_bundles = storage.get_pending_bundles().await?;

        let service = Self {
            inner: Arc::new(InteropServiceInner::new(
                tx_service_handles.clone(),
                liquidity_tracker,
                storage.clone(),
                providers,
            )),
            command_rx,
        };

        let handle = InteropServiceHandle { command_tx, storage: storage.clone() };

        // Spawn the refund monitor service with configured interval
        RefundMonitorService::with_interval(
            storage,
            handle.clone(),
            interop_config.refund_check_interval,
        )
        .spawn();

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
        assert!(Init.can_transition_to(&SourceQueued));
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
        assert!(SettlementsQueued.can_transition_to(&SettlementsConfirmed));
        assert!(SettlementsConfirmed.can_transition_to(&Done));
        assert!(RefundsScheduled.can_transition_to(&RefundsReady));
        assert!(RefundsReady.can_transition_to(&RefundsQueued));
        assert!(RefundsQueued.can_transition_to(&Failed));

        // Invalid transitions
        assert!(!Init.can_transition_to(&SourceConfirmed));
        assert!(!Init.can_transition_to(&Done));
        assert!(!SourceQueued.can_transition_to(&DestinationQueued));
        assert!(!DestinationConfirmed.can_transition_to(&SourceQueued));
        assert!(!Done.can_transition_to(&Init));
        assert!(!Failed.can_transition_to(&Init));
        assert!(!RefundsQueued.can_transition_to(&RefundsScheduled));
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

        // Update status
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
            tx_handles.clone(),
            LiquidityTracker::new(providers.clone(), funder),
            storage,
            providers,
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
