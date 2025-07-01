use super::{
    RelayTransaction, TransactionFailureReason, TransactionServiceHandle, TransactionStatus, TxId,
};
use crate::{
    error::StorageError,
    storage::{RelayStorage, StorageApi},
    types::{IERC20, OrchestratorContract::IntentExecuted, rpc::BundleId},
};
use alloy::{
    primitives::{Address, BlockNumber, ChainId, U256, map::HashMap},
    providers::{DynProvider, MulticallError, Provider},
    rpc::types::TransactionReceipt,
};
use futures_util::future::TryJoinAll;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
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
    /// Source chain transactions (can be IDs or full transactions)
    pub src_txs: Vec<TxIdOrTx>,
    /// Destination chain transactions (can be IDs or full transactions)
    pub dst_txs: Vec<TxIdOrTx>,
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
        self.src_txs.push(TxIdOrTx::Tx(Box::new(tx)));
    }

    /// Appends a destination transaction to the bundle and updates asset transfers
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

        self.dst_txs.push(TxIdOrTx::Tx(Box::new(tx)));
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
    /// Not enough liquidity.
    #[error("don't have enough liquidity for the bundle")]
    NotEnoughLiquidity,
    /// Storage error.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// An error occurred during ABI encoding/decoding.
    #[error(transparent)]
    AbiError(#[from] alloy::sol_types::Error),
    /// Multicall error.
    #[error(transparent)]
    MulticallError(#[from] MulticallError),
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
}

/// Represents either a transaction ID or full transaction data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TxIdOrTx {
    /// Just the transaction ID (for backwards compatibility or when tx is already stored)
    Id(TxId),
    /// Full transaction data (for recovery)
    Tx(Box<RelayTransaction>),
}

impl TxIdOrTx {
    /// Get the transaction ID regardless of variant
    pub fn id(&self) -> TxId {
        match self {
            TxIdOrTx::Id(id) => *id,
            TxIdOrTx::Tx(tx) => tx.id,
        }
    }

    /// Try to get the full transaction if available
    pub fn transaction(&self) -> Option<&RelayTransaction> {
        match self {
            TxIdOrTx::Id(_) => None,
            TxIdOrTx::Tx(tx) => Some(tx),
        }
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

    /// Handle the Init status - check liquidity and queue source transactions
    ///
    /// Transitions to: [`BundleStatus::SourceQueued`]
    async fn on_init(&self, bundle: &mut BundleWithStatus) -> Result<(), InteropBundleError> {
        tracing::info!(bundle_id = ?bundle.bundle.id, "Initializing bundle");

        // Extract source transactions before update (since update will modify the bundle)
        let src_transactions: Vec<RelayTransaction> = bundle
            .bundle
            .src_txs
            .iter()
            .filter_map(|tx| match tx {
                TxIdOrTx::Tx(tx) => Some((**tx).clone()),
                TxIdOrTx::Id(_) => None,
            })
            .collect();

        // Update status and queue source transactions atomically
        bundle.status = BundleStatus::SourceQueued;
        self.storage
            .update_bundle_and_queue_transactions(&mut bundle.bundle, bundle.status, true)
            .await?;

        // Send the transactions
        self.send_transactions(&src_transactions).await?;

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
        match self.process_source_transactions(&bundle.bundle).await {
            Ok(()) => {
                // Update status to source confirmed
                bundle.status = BundleStatus::SourceConfirmed;
            }
            Err(e) => {
                // Update status to source failures
                tracing::error!(bundle_id = ?bundle.bundle.id, error = ?e, "Source transactions failed");
                bundle.status = BundleStatus::SourceFailures;
            }
        }

        self.storage.update_pending_bundle_status(bundle.bundle.id, bundle.status).await?;
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

        // Extract destination transactions before update.
        let dst_transactions: Vec<RelayTransaction> = bundle
            .bundle
            .dst_txs
            .iter()
            .filter_map(|tx| match tx {
                TxIdOrTx::Tx(tx) => Some((**tx).clone()),
                TxIdOrTx::Id(_) => None,
            })
            .collect();

        // Update status and queue destination transactions atomically
        bundle.status = BundleStatus::DestinationQueued;
        self.storage
            .update_bundle_and_queue_transactions(&mut bundle.bundle, bundle.status, false)
            .await?;

        // Send the transactions
        self.send_transactions(&dst_transactions).await?;

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
        bundle.status = BundleStatus::Failed;
        self.storage.update_pending_bundle_status(bundle.bundle.id, bundle.status).await?;
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
        match self.process_destination_transactions(&bundle.bundle).await {
            Ok(()) => {
                // Update status to destination confirmed
                bundle.status = BundleStatus::DestinationConfirmed;
            }
            Err(e) => {
                // Update status to destination failures
                tracing::error!(bundle_id = ?bundle.bundle.id, error = ?e, "Destination transactions failed");
                bundle.status = BundleStatus::DestinationFailures;
            }
        }

        self.storage.update_pending_bundle_status(bundle.bundle.id, bundle.status).await?;
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
        bundle.status = BundleStatus::Failed;
        self.storage.update_pending_bundle_status(bundle.bundle.id, bundle.status).await?;

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
        bundle.status = BundleStatus::WithdrawalsQueued;
        self.storage.update_pending_bundle_status(bundle.bundle.id, bundle.status).await?;
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
        bundle.status = BundleStatus::Failed;
        self.storage.update_pending_bundle_status(bundle.bundle.id, bundle.status).await?;
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

        bundle.status = BundleStatus::Done;
        self.storage.update_pending_bundle_status(bundle.bundle.id, bundle.status).await?;
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

    /// Check the status of transactions by their IDs.
    async fn check_transaction_statuses(
        &self,
        tx_ids: &[TxId],
    ) -> Result<Vec<Option<(ChainId, TransactionStatus)>>, InteropBundleError> {
        let statuses = futures_util::future::try_join_all(
            tx_ids.iter().map(|tx_id| self.storage.read_transaction_status(*tx_id)),
        )
        .await?;

        Ok(statuses)
    }

    /// Send transactions that are already queued.
    async fn send_transactions(
        &self,
        transactions: &[RelayTransaction],
    ) -> Result<(), InteropBundleError> {
        for tx in transactions {
            self.tx_service_handles
                .get(&tx.chain_id())
                .ok_or_else(|| {
                    let err =
                        Arc::new(format!("no transaction service for chain {}", tx.chain_id()));
                    InteropBundleError::TransactionError(err)
                })?
                .send_transaction_no_queue(tx.clone());
        }

        Ok(())
    }

    /// Watch transactions until they complete.
    async fn watch_transactions(
        &self,
        tx_ids: impl Iterator<Item = TxId>,
    ) -> Result<
        Vec<(TxId, Result<TransactionReceipt, Arc<dyn TransactionFailureReason>>)>,
        InteropBundleError,
    > {
        let mut pending: HashSet<TxId> = tx_ids.collect();
        let mut results = Vec::with_capacity(pending.len());

        while !pending.is_empty() {
            let pending_vec: Vec<TxId> = pending.iter().copied().collect();
            let statuses = self.check_transaction_statuses(&pending_vec).await?;

            for (tx_id, status) in pending_vec.iter().zip(statuses.iter()) {
                if let Some((_, status)) = status {
                    match status {
                        TransactionStatus::Confirmed(receipt) => {
                            tracing::debug!(tx_id = ?tx_id, "Transaction confirmed");
                            // Check for IntentExecuted event and verify no errors
                            let event = IntentExecuted::try_from_receipt(receipt);
                            if event.as_ref().is_none_or(|e| e.has_error()) {
                                let reason =
                                    event.as_ref().map(|e| e.err.to_string()).unwrap_or_else(
                                        || "IntentExecuted event not found".to_string(),
                                    );
                                let err = Arc::new(format!("intent failed: {reason}"))
                                    as Arc<dyn TransactionFailureReason>;
                                results.push((*tx_id, Err(err)));
                                pending.remove(tx_id);
                            } else {
                                results.push((*tx_id, Ok(*receipt.clone())));
                                pending.remove(tx_id);
                            }
                        }
                        TransactionStatus::Failed(err) => {
                            tracing::warn!(tx_id = ?tx_id, "Transaction failed");
                            results.push((*tx_id, Err(err.clone())));
                            pending.remove(tx_id);
                        }
                        TransactionStatus::InFlight | TransactionStatus::Pending(_) => {
                            tracing::trace!(tx_id = ?tx_id, "Transaction still pending");
                        }
                    }
                }
            }

            if !pending.is_empty() {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }

        Ok(results)
    }

    /// Process source transactions for a bundle.
    ///
    /// Waits for all source transactions to complete.
    async fn process_source_transactions(
        &self,
        bundle: &InteropBundle,
    ) -> Result<(), InteropBundleError> {
        // Wait for all transactions to complete
        // Transactions were already queued by update_bundle_and_queue_transactions
        let results = self.watch_transactions(bundle.src_txs.iter().map(|tx| tx.id())).await?;

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
    ) -> Result<(), InteropBundleError> {
        let mut maybe_err = Ok(());

        // Wait for all transactions to complete
        // Transactions were already queued by update_bundle_and_queue_transactions
        let results = self.watch_transactions(bundle.dst_txs.iter().map(|tx| tx.id())).await?;

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
            let block = receipts.get(&tx.id()).and_then(|r| r.block_number).unwrap_or_default();

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

        let liquidity_tracker = LiquidityTracker::new(providers, funder_address);
        let pending_bundles = storage.get_pending_bundles().await?;

        let service = Self {
            inner: Arc::new(InteropServiceInner::new(
                tx_service_handles,
                liquidity_tracker,
                storage.clone(),
            )),
            command_rx,
        };

        let handle = InteropServiceHandle { command_tx, storage };

        for bundle in pending_bundles {
            tracing::info!(
                bundle_id = ?bundle.bundle.id,
                status = ?bundle.status,
                src_count = bundle.bundle.src_txs.len(),
                dst_count = bundle.bundle.dst_txs.len(),
                "Resume pending interop bundles from disk"
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
                    let inner = Arc::clone(&self.inner);
                    tokio::spawn(async move {
                        if let Err(e) = inner.send_and_watch_bundle_with_status(*bundle).await {
                            error!("Failed to process interop bundle: {:?}", e);
                        }
                    });
                }
            }
        }

        Poll::Pending
    }
}
