//! Relay storage

mod api;
pub use api::StorageApi;

mod memory;
mod pg;

use crate::{
    transactions::{PendingTransaction, RelayTransaction, TransactionStatus, TxId},
    types::{CreatableAccount, KeyID, rpc::BundleId},
};
use alloy::{
    consensus::TxEnvelope,
    primitives::{Address, ChainId},
};
use async_trait::async_trait;
use sqlx::PgPool;
use std::sync::Arc;

/// Relay storage interface.
#[derive(Debug, Clone)]
pub struct RelayStorage {
    inner: Arc<dyn StorageApi>,
}

impl RelayStorage {
    /// Create [`RelayStorage`] with a in-memory backend.
    pub fn in_memory() -> Self {
        Self { inner: Arc::new(memory::InMemoryStorage::default()) }
    }

    /// Create a [`RelayStorage`] with a PostgreSQL backend.
    pub fn pg(pool: PgPool) -> Self {
        Self { inner: Arc::new(pg::PgStorage::new(pool)) }
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

    async fn read_accounts_from_id(&self, id: &KeyID) -> api::Result<Vec<Address>> {
        self.inner.read_accounts_from_id(id).await
    }

    async fn replace_queued_tx_with_pending(&self, tx: &PendingTransaction) -> api::Result<()> {
        self.inner.replace_queued_tx_with_pending(tx).await
    }

    async fn add_pending_envelope(&self, tx_id: TxId, envelope: &TxEnvelope) -> api::Result<()> {
        self.inner.add_pending_envelope(tx_id, envelope).await
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

    async fn read_transaction_status(
        &self,
        tx: TxId,
    ) -> api::Result<Option<(ChainId, TransactionStatus)>> {
        self.inner.read_transaction_status(tx).await
    }

    async fn add_bundle_tx(
        &self,
        bundle: BundleId,
        chain_id: ChainId,
        tx: TxId,
    ) -> api::Result<()> {
        self.inner.add_bundle_tx(bundle, chain_id, tx).await
    }

    async fn get_bundle_transactions(&self, bundle: BundleId) -> api::Result<Vec<TxId>> {
        self.inner.get_bundle_transactions(bundle).await
    }

    async fn write_queued_transaction(&self, tx: &RelayTransaction) -> api::Result<()> {
        self.inner.write_queued_transaction(tx).await
    }

    async fn read_queued_transactions(&self, chain_id: u64) -> api::Result<Vec<RelayTransaction>> {
        self.inner.read_queued_transactions(chain_id).await
    }
}
