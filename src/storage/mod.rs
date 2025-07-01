//! Relay storage

mod api;
use alloy::primitives::{BlockNumber, U256};
pub use api::{LockLiquidityInput, StorageApi};

mod memory;
mod pg;

use crate::{
    liquidity::{
        ChainAddress,
        bridge::{Transfer, TransferId, TransferState},
    },
    transactions::{PendingTransaction, RelayTransaction, TransactionStatus, TxId},
    types::{CreatableAccount, rpc::BundleId},
};
use alloy::{
    consensus::TxEnvelope,
    primitives::{Address, ChainId, map::HashMap},
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
    async fn read_account(&self, address: &Address) -> api::Result<Option<CreatableAccount>> {
        self.inner.read_account(address).await
    }

    async fn write_account(&self, account: CreatableAccount) -> api::Result<()> {
        self.inner.write_account(account).await
    }

    async fn replace_queued_tx_with_pending(&self, tx: &PendingTransaction) -> api::Result<()> {
        self.inner.replace_queued_tx_with_pending(tx).await
    }

    async fn remove_queued(&self, tx_id: TxId) -> api::Result<()> {
        self.inner.remove_queued(tx_id).await
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

    async fn verified_email_exists(&self, email: &str) -> api::Result<bool> {
        self.inner.verified_email_exists(email).await
    }

    async fn add_unverified_email(
        &self,
        account: Address,
        email: &str,
        token: &str,
    ) -> api::Result<()> {
        self.inner.add_unverified_email(account, email, token).await
    }

    async fn verify_email(&self, account: Address, email: &str, token: &str) -> api::Result<bool> {
        self.inner.verify_email(account, email, token).await
    }

    async fn ping(&self) -> api::Result<()> {
        self.inner.ping().await
    }

    async fn try_lock_liquidity(
        &self,
        assets: HashMap<ChainAddress, LockLiquidityInput>,
    ) -> api::Result<()> {
        self.inner.try_lock_liquidity(assets).await
    }

    async fn unlock_liquidity(
        &self,
        asset: ChainAddress,
        amount: U256,
        at: BlockNumber,
    ) -> api::Result<()> {
        self.inner.unlock_liquidity(asset, amount, at).await
    }

    async fn get_total_locked_at(&self, asset: ChainAddress, at: BlockNumber) -> api::Result<U256> {
        self.inner.get_total_locked_at(asset, at).await
    }

    async fn prune_unlocked_entries(
        &self,
        chain_id: ChainId,
        until: BlockNumber,
    ) -> api::Result<()> {
        self.inner.prune_unlocked_entries(chain_id, until).await
    }

    async fn lock_liquidity_for_bridge(
        &self,
        transfer: &Transfer,
        input: LockLiquidityInput,
    ) -> api::Result<()> {
        self.inner.lock_liquidity_for_bridge(transfer, input).await
    }

    async fn update_transfer_bridge_data(
        &self,
        transfer_id: TransferId,
        data: &serde_json::Value,
    ) -> api::Result<()> {
        self.inner.update_transfer_bridge_data(transfer_id, data).await
    }

    async fn get_transfer_bridge_data(
        &self,
        transfer_id: TransferId,
    ) -> api::Result<Option<serde_json::Value>> {
        self.inner.get_transfer_bridge_data(transfer_id).await
    }

    async fn update_transfer_state(
        &self,
        transfer_id: TransferId,
        state: TransferState,
    ) -> api::Result<()> {
        self.inner.update_transfer_state(transfer_id, state).await
    }

    async fn update_transfer_state_and_unlock_liquidity(
        &self,
        transfer_id: TransferId,
        state: TransferState,
    ) -> api::Result<()> {
        self.inner.update_transfer_state_and_unlock_liquidity(transfer_id, state).await
    }

    async fn get_transfer_state(
        &self,
        transfer_id: TransferId,
    ) -> api::Result<Option<TransferState>> {
        self.inner.get_transfer_state(transfer_id).await
    }

    async fn load_pending_transfers(&self) -> api::Result<Vec<Transfer>> {
        self.inner.load_pending_transfers().await
    }
}
