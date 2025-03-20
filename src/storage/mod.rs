//! Relay storage

mod api;
pub use api::StorageApi;
mod error;
use async_trait::async_trait;
pub use error::StorageError;
mod memory;

use crate::{
    transactions::{PendingTransaction, TransactionStatus},
    types::{PREPAccount, rpc::BundleId},
};
use alloy::primitives::Address;
use std::sync::Arc;

/// Relay storage interface.
#[derive(Debug, Clone)]
pub struct RelayStorage {
    inner: Arc<dyn StorageApi>,
}

impl RelayStorage {
    /// Create [`RelayStorage`] with a in-memory backend. Used for testing only.
    pub fn in_memory() -> Self {
        Self { inner: Arc::new(memory::InMemoryStorage::default()) }
    }
}

#[async_trait]
impl StorageApi for RelayStorage {
    async fn read_prep(&self, address: &Address) -> api::Result<Option<PREPAccount>> {
        self.inner.read_prep(address).await
    }

    async fn write_prep(&self, account: &PREPAccount) -> api::Result<()> {
        self.inner.write_prep(account).await
    }

    async fn write_pending_transaction(&self, tx: &PendingTransaction) -> api::Result<()> {
        self.inner.write_pending_transaction(tx).await
    }

    async fn remove_pending_transaction(&self, tx_id: BundleId) -> api::Result<()> {
        self.inner.remove_pending_transaction(tx_id).await
    }

    async fn read_pending_transactions(
        &self,
        signer: Address,
        chain_id: u64,
    ) -> api::Result<Vec<PendingTransaction>> {
        self.inner.read_pending_transactions(signer, chain_id).await
    }

    async fn write_transaction_status(
        &self,
        tx: BundleId,
        status: &TransactionStatus,
    ) -> api::Result<()> {
        self.inner.write_transaction_status(tx, status).await
    }

    async fn read_transaction_status(
        &self,
        tx: BundleId,
    ) -> api::Result<Option<TransactionStatus>> {
        self.inner.read_transaction_status(tx).await
    }
}
