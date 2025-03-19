//! Relay storage api.

use super::StorageError;
use crate::{
    transactions::{PendingTransaction, TransactionStatus},
    types::{PREPAccount, rpc::BundleId},
};
use alloy::primitives::{Address, B256};
use async_trait::async_trait;
use std::fmt::Debug;

/// Type alias for `Result<T, StorageError>`
pub type Result<T> = core::result::Result<T, StorageError>;

/// Storage API.
#[async_trait]
pub trait StorageApi: Debug + Send + Sync {
    /// Reads [`PREPAccount`] from storage.
    async fn read_prep(&self, address: &Address) -> Result<Option<PREPAccount>>;

    /// Writes [`PREPAccount`] to storage.
    async fn write_prep(&self, account: &PREPAccount) -> Result<()>;

    /// Writes a pending transaction to storage.
    async fn write_pending_transaction(&self, tx: &PendingTransaction) -> Result<()>;

    /// Removes a pending transaction from storage.
    async fn remove_pending_transaction(&self, tx_id: B256) -> Result<()>;

    /// Reads a pending transaction from storage.
    async fn read_pending_transactions(
        &self,
        signer: Address,
        chain_id: u64,
    ) -> Result<Vec<PendingTransaction>>;

    /// Saves a transaction status.
    async fn write_transaction_status(
        &self,
        tx: BundleId,
        status: &TransactionStatus,
    ) -> Result<()>;

    /// Reads a transaction status.
    async fn read_transaction_status(&self, tx: BundleId) -> Result<Option<TransactionStatus>>;
}
