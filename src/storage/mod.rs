//! Relay storage

mod api;
pub use api::StorageApi;
mod memory;

use crate::{
    transactions::{PendingTransaction, TransactionStatus, TxId},
    types::{CreatableAccount, rpc::BundleId},
};
use alloy::primitives::Address;
use async_trait::async_trait;
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
    async fn read_prep(&self, address: &Address) -> api::Result<Option<CreatableAccount>> {
        self.inner.read_prep(address).await
    }

    async fn write_prep(&self, account: CreatableAccount) -> api::Result<()> {
        self.inner.write_prep(account).await
    }

    async fn read_accounts_from_id(&self, id: &Address) -> api::Result<Option<Vec<Address>>> {
        self.inner.read_accounts_from_id(id).await
    }

    async fn write_pending_transaction(&self, tx: &PendingTransaction) -> api::Result<()> {
        self.inner.write_pending_transaction(tx).await
    }

    async fn remove_pending_transaction(&self, tx_id: TxId) -> api::Result<()> {
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
        tx: TxId,
        status: &TransactionStatus,
    ) -> api::Result<()> {
        self.inner.write_transaction_status(tx, status).await
    }

    async fn read_transaction_status(&self, tx: TxId) -> api::Result<Option<TransactionStatus>> {
        self.inner.read_transaction_status(tx).await
    }

    async fn add_bundle_tx(&self, bundle: BundleId, tx: TxId) -> api::Result<()> {
        self.inner.add_bundle_tx(bundle, tx).await
    }

    async fn get_bundle_transactions(&self, bundle: BundleId) -> api::Result<Vec<TxId>> {
        self.inner.get_bundle_transactions(bundle).await
    }
}
