//! Relay storage api.

use crate::{
    error::StorageError,
    transactions::{
        PendingTransaction, RelayTransaction, TransactionStatus, TxId,
        interop::{BundleStatus, BundleWithStatus, InteropBundle},
    },
    types::{CreatableAccount, InteropTxType, rpc::BundleId},
};
use alloy::{
    consensus::TxEnvelope,
    primitives::{Address, ChainId},
};
use async_trait::async_trait;
use std::fmt::Debug;

/// Type alias for `Result<T, StorageError>`
pub type Result<T> = core::result::Result<T, StorageError>;

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

    /// Atomically update bundle status and queue transactions.
    ///
    /// # Arguments
    /// * `bundle` - The bundle containing transactions to queue
    /// * `status` - The new status for the bundle
    /// * `tx_type` - Specifies whether to queue source or destination transactions
    async fn queue_bundle_transactions(
        &self,
        bundle: &InteropBundle,
        status: BundleStatus,
        tx_type: InteropTxType,
    ) -> Result<()>;

    /// Moves a bundle from pending_bundles to finished_bundles table.
    /// This is called when a bundle reaches a terminal state (Done or Failed).
    async fn move_bundle_to_finished(&self, bundle_id: BundleId) -> Result<()>;
}
