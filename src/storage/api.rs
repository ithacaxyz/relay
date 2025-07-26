//! Relay storage api.

use crate::{
    error::StorageError,
    liquidity::{
        ChainAddress,
        bridge::{BridgeTransfer, BridgeTransferId, BridgeTransferState},
    },
    transactions::{
        PendingTransaction, PullGasState, RelayTransaction, TransactionStatus, TxId,
        interop::{BundleStatus, BundleWithStatus, InteropBundle},
    },
    types::{CreatableAccount, rpc::BundleId},
};
use alloy::{
    consensus::TxEnvelope,
    primitives::{Address, B256, BlockNumber, ChainId, U256, map::HashMap},
    rpc::types::TransactionReceipt,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// Type alias for `Result<T, StorageError>`
pub type Result<T> = core::result::Result<T, StorageError>;

/// Input for [`StorageApi::try_lock_liquidity`].
#[derive(Debug, Serialize, Deserialize)]
pub struct LockLiquidityInput {
    /// Current balance of the asset fetched from provider.
    pub current_balance: U256,
    /// Block number at which the balance was fetched.
    pub block_number: BlockNumber,
    /// Amount of the asset we are trying to lock.
    pub lock_amount: U256,
}

/// Storage API.
#[async_trait]
pub trait StorageApi: Debug + Send + Sync {
    /// Reads [`CreatableAccount`] from storage.
    async fn read_account(&self, address: &Address) -> Result<Option<CreatableAccount>>;

    /// Writes [`CreatableAccount`] to storage.
    async fn write_account(&self, account: CreatableAccount) -> Result<()>;

    /// Replaces previously queued transaction with a pending transaction.
    async fn replace_queued_tx_with_pending(&self, tx: &PendingTransaction) -> Result<()>;

    /// Removes a queued transaction from storage.
    async fn remove_queued(&self, tx_id: TxId) -> Result<()>;

    /// Pushes a new [`TxEnvelope`] to [`PendingTransaction::sent`].
    async fn add_pending_envelope(&self, tx_id: TxId, envelope: &TxEnvelope) -> Result<()>;

    /// Removes a pending transaction from storage.
    async fn remove_pending_transaction(&self, tx_id: TxId) -> Result<()>;

    /// Reads pending transactions for the given signer and chain id from storage.
    async fn read_pending_transactions(
        &self,
        signer: Address,
        chain_id: u64,
    ) -> Result<Vec<PendingTransaction>>;

    /// Saves a transaction status.
    async fn write_transaction_status(&self, tx: TxId, status: &TransactionStatus) -> Result<()>;

    /// Reads a transaction status.
    async fn read_transaction_status(
        &self,
        tx: TxId,
    ) -> Result<Option<(ChainId, TransactionStatus)>>;

    /// Adds a transaction to a bundle.
    async fn add_bundle_tx(&self, bundle: BundleId, tx: TxId) -> Result<()>;

    /// Gets all transactions in a bundle.
    async fn get_bundle_transactions(&self, bundle: BundleId) -> Result<Vec<TxId>>;

    /// Writes a queued transaction.
    async fn queue_transaction(&self, tx: &RelayTransaction) -> Result<()>;

    /// Reads queued transactions for the given chain.
    async fn read_queued_transactions(&self, chain_id: u64) -> Result<Vec<RelayTransaction>>;

    /// Checks if a verified email exists.
    async fn verified_email_exists(&self, email: &str) -> Result<bool>;

    /// Adds an unverified email to the database.
    async fn add_unverified_email(&self, account: Address, email: &str, token: &str) -> Result<()>;

    /// Verifies an unverified email in the database if the verification code is valid.
    ///
    /// Should remove any other verified emails for the same account address.
    ///
    /// Returns true if the email was verified successfully.
    async fn verify_email(&self, account: Address, email: &str, token: &str) -> Result<bool>;

    /// Pings the database, checking if the connection is alive.
    async fn ping(&self) -> Result<()>;

    /// Stores a new pending bundle.
    async fn store_pending_bundle(
        &self,
        bundle: &InteropBundle,
        status: BundleStatus,
    ) -> Result<()>;

    /// Updates an existing pending bundle's status.
    async fn update_pending_bundle_status(
        &self,
        bundle_id: BundleId,
        status: BundleStatus,
    ) -> Result<()>;

    /// Gets all pending bundles.
    async fn get_pending_bundles(&self) -> Result<Vec<BundleWithStatus>>;

    /// Gets a specific pending bundle by ID.
    async fn get_pending_bundle(&self, bundle_id: BundleId) -> Result<Option<BundleWithStatus>>;

    /// Atomically update bundle data and queue specific transactions.
    /// Used when you need to update the bundle and queue transactions atomically.
    ///
    /// # Arguments
    /// * `bundle` - The bundle to update
    /// * `status` - The new status for the bundle
    /// * `transactions` - Specific transactions to queue
    async fn update_bundle_and_queue_transactions(
        &self,
        bundle: &InteropBundle,
        status: BundleStatus,
        transactions: &[RelayTransaction],
    ) -> Result<()>;

    /// Moves a bundle from pending_bundles to finished_bundles table.
    /// This is called when a bundle reaches a terminal state (Done or Failed).
    async fn move_bundle_to_finished(&self, bundle_id: BundleId) -> Result<()>;
    /// Gets the interop status for a bundle by checking both pending and finished tables.
    async fn get_interop_status(&self, bundle_id: BundleId) -> Result<Option<BundleStatus>>;

    /// Stores a pending refund for a bundle with the maximum refund timestamp and atomically
    /// updates the bundle status.
    async fn store_pending_refund(
        &self,
        bundle_id: BundleId,
        refund_timestamp: DateTime<Utc>,
        new_status: BundleStatus,
    ) -> Result<()>;

    /// Gets all pending refunds that are ready to be processed (refund_timestamp <= current time).
    async fn get_pending_refunds_ready(
        &self,
        current_time: DateTime<Utc>,
    ) -> Result<Vec<(BundleId, DateTime<Utc>)>>;

    /// Removes a processed refund from pending refunds.
    async fn remove_processed_refund(&self, bundle_id: BundleId) -> Result<()>;

    /// Atomically marks a refund as ready by updating bundle status and removing it from the
    /// scheduler.
    async fn mark_refund_ready(&self, bundle_id: BundleId, new_status: BundleStatus) -> Result<()>;

    /// Attempts to lock liquidity for the given assets corresponding to an interop bundle, and
    /// updates the bundle status to the given status.
    async fn lock_liquidity_for_bundle(
        &self,
        assets: HashMap<ChainAddress, LockLiquidityInput>,
        bundle_id: BundleId,
        status: BundleStatus,
    ) -> Result<()>;

    /// Unlocks liquidity for the given [`InteropBundle`] and updates its status.
    async fn unlock_bundle_liquidity(
        &self,
        bundle: &InteropBundle,
        receipts: HashMap<TxId, TransactionReceipt>,
        status: BundleStatus,
    ) -> Result<()>;

    /// Gets total locked liquidity for the given asset.
    async fn get_total_locked_at(&self, asset: ChainAddress, at: BlockNumber) -> Result<U256>;

    /// Removes unlocked entries up until the given block number (inclusive), including it and
    /// subtracts them from the total locked amount.
    async fn prune_unlocked_entries(&self, chain_id: ChainId, until: BlockNumber) -> Result<()>;

    /// Atomically locks liquidity for a bridge transfer and creates an entry for the transfer in
    /// the database.
    async fn lock_liquidity_for_bridge(
        &self,
        transfer: &BridgeTransfer,
        input: LockLiquidityInput,
    ) -> Result<()>;

    /// Updates a bridge-specific data for a transfer.
    async fn update_transfer_bridge_data(
        &self,
        transfer_id: BridgeTransferId,
        data: &serde_json::Value,
    ) -> Result<()>;

    /// Gets bridge-specific data for a transfer.
    async fn get_transfer_bridge_data(
        &self,
        transfer_id: BridgeTransferId,
    ) -> Result<Option<serde_json::Value>>;

    /// Updates transfer state.
    async fn update_transfer_state(
        &self,
        transfer_id: BridgeTransferId,
        state: BridgeTransferState,
    ) -> Result<()>;

    /// Updates transfer state and unlocks liquidity for it.
    ///
    /// This is essentially a helper to call `update_transfer_state` and `unlock_liquidity`
    /// atomically.
    async fn update_transfer_state_and_unlock_liquidity(
        &self,
        transfer_id: BridgeTransferId,
        state: BridgeTransferState,
        at: BlockNumber,
    ) -> Result<()>;

    /// Gets the current state of a bridge transfer.
    async fn get_transfer_state(
        &self,
        transfer_id: BridgeTransferId,
    ) -> Result<Option<BridgeTransferState>>;

    /// Loads all pending transfers from storage.
    ///
    /// This returns transfers in states that require monitoring:
    /// - Pending: Initial state, waiting to be sent
    /// - Sent: Outbound transaction sent, monitoring for completion
    async fn load_pending_transfers(&self) -> Result<Vec<BridgeTransfer>>;

    /// Atomically locks liquidity for a pull gas transaction and creates a tracking record.
    async fn lock_liquidity_for_pull_gas(
        &self,
        transaction: &TxEnvelope,
        signer: Address,
        input: LockLiquidityInput,
    ) -> Result<()>;

    /// Updates pull gas transaction state and unlocks liquidity.
    async fn update_pull_gas_and_unlock_liquidity(
        &self,
        tx_hash: B256,
        chain_id: ChainId,
        amount: U256,
        state: PullGasState,
        at: BlockNumber,
    ) -> Result<()>;

    /// Loads pending pull gas transactions for a signer.
    async fn load_pending_pull_gas_transactions(
        &self,
        signer: Address,
        chain_id: ChainId,
    ) -> Result<Vec<TxEnvelope>>;
}
