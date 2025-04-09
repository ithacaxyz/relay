//! Relay storage api.

use crate::{
    error::StorageError,
    transactions::{PendingTransaction, TransactionStatus, TxId},
    types::{CreatableAccount, KeyID, rpc::BundleId},
};
use alloy::primitives::{Address, ChainId};
use async_trait::async_trait;
use std::fmt::Debug;

/// Type alias for `Result<T, StorageError>`
pub type Result<T> = core::result::Result<T, StorageError>;

/// Storage API.
#[async_trait]
pub trait StorageApi: Debug + Send + Sync {
    /// Reads [`PREPAccount`] from storage.
    async fn read_prep(&self, address: &Address) -> Result<Option<CreatableAccount>>;

    /// Writes [`PREPAccount`] to storage.
    async fn write_prep(&self, account: CreatableAccount) -> Result<()>;

    /// Reads all account addresses associated with a ID.
    async fn read_accounts_from_id(&self, id: &KeyID) -> Result<Vec<Address>>;

    /// Writes a pending transaction to storage.
    async fn write_pending_transaction(&self, tx: &PendingTransaction) -> Result<()>;

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
    async fn add_bundle_tx(&self, bundle: BundleId, chain_id: ChainId, tx: TxId) -> Result<()>;

    /// Gets all transactions in a bundle.
    async fn get_bundle_transactions(&self, bundle: BundleId) -> Result<Vec<TxId>>;
}
