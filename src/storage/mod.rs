//! Relay storage

mod api;
pub use crate::{
    transactions::interop::{BundleStatus, BundleWithStatus, InteropBundle},
    types::InteropTxType,
};
use alloy::{
    primitives::{BlockNumber, U256},
    rpc::types::TransactionReceipt,
};
pub use api::{LockLiquidityInput, StorageApi};

mod memory;
mod pg;

use crate::{
    liquidity::{
        ChainAddress,
        bridge::{BridgeTransfer, BridgeTransferId, BridgeTransferState},
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

    async fn add_bundle_tx(&self, bundle: BundleId, tx: TxId) -> api::Result<()> {
        self.inner.add_bundle_tx(bundle, tx).await
    }

    async fn get_bundle_transactions(&self, bundle: BundleId) -> api::Result<Vec<TxId>> {
        self.inner.get_bundle_transactions(bundle).await
    }

    async fn queue_transaction(&self, tx: &RelayTransaction) -> api::Result<()> {
        self.inner.queue_transaction(tx).await
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

    async fn store_pending_bundle(
        &self,
        bundle: &InteropBundle,
        status: BundleStatus,
    ) -> api::Result<()> {
        self.inner.store_pending_bundle(bundle, status).await
    }

    async fn update_pending_bundle_status(
        &self,
        bundle_id: BundleId,
        status: BundleStatus,
    ) -> api::Result<()> {
        self.inner.update_pending_bundle_status(bundle_id, status).await
    }

    async fn get_pending_bundles(&self) -> api::Result<Vec<BundleWithStatus>> {
        self.inner.get_pending_bundles().await
    }

    async fn get_pending_bundle(
        &self,
        bundle_id: BundleId,
    ) -> api::Result<Option<BundleWithStatus>> {
        self.inner.get_pending_bundle(bundle_id).await
    }

    async fn update_bundle_and_queue_transactions(
        &self,
        bundle: &InteropBundle,
        status: BundleStatus,
        transactions: &[RelayTransaction],
    ) -> api::Result<()> {
        self.inner.update_bundle_and_queue_transactions(bundle, status, transactions).await
    }

    async fn move_bundle_to_finished(&self, bundle_id: BundleId) -> api::Result<()> {
        self.inner.move_bundle_to_finished(bundle_id).await
    }

    async fn store_pending_refund(
        &self,
        bundle_id: BundleId,
        refund_timestamp: chrono::DateTime<chrono::Utc>,
        new_status: BundleStatus,
    ) -> api::Result<()> {
        self.inner.store_pending_refund(bundle_id, refund_timestamp, new_status).await
    }

    async fn get_pending_refunds_ready(
        &self,
        current_time: chrono::DateTime<chrono::Utc>,
    ) -> api::Result<Vec<(BundleId, chrono::DateTime<chrono::Utc>)>> {
        self.inner.get_pending_refunds_ready(current_time).await
    }

    async fn remove_processed_refund(&self, bundle_id: BundleId) -> api::Result<()> {
        self.inner.remove_processed_refund(bundle_id).await
    }

    async fn mark_refund_ready(
        &self,
        bundle_id: BundleId,
        new_status: BundleStatus,
    ) -> api::Result<()> {
        self.inner.mark_refund_ready(bundle_id, new_status).await
    }

    async fn lock_liquidity_for_bundle(
        &self,
        assets: HashMap<ChainAddress, LockLiquidityInput>,
        bundle_id: BundleId,
        status: BundleStatus,
    ) -> api::Result<()> {
        self.inner.lock_liquidity_for_bundle(assets, bundle_id, status).await
    }

    async fn unlock_bundle_liquidity(
        &self,
        bundle: &InteropBundle,
        receipts: HashMap<TxId, TransactionReceipt>,
        status: BundleStatus,
    ) -> api::Result<()> {
        self.inner.unlock_bundle_liquidity(bundle, receipts, status).await
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
        transfer: &BridgeTransfer,
        input: LockLiquidityInput,
    ) -> api::Result<()> {
        self.inner.lock_liquidity_for_bridge(transfer, input).await
    }

    async fn update_transfer_bridge_data(
        &self,
        transfer_id: BridgeTransferId,
        data: &serde_json::Value,
    ) -> api::Result<()> {
        self.inner.update_transfer_bridge_data(transfer_id, data).await
    }

    async fn get_transfer_bridge_data(
        &self,
        transfer_id: BridgeTransferId,
    ) -> api::Result<Option<serde_json::Value>> {
        self.inner.get_transfer_bridge_data(transfer_id).await
    }

    async fn update_transfer_state(
        &self,
        transfer_id: BridgeTransferId,
        state: BridgeTransferState,
    ) -> api::Result<()> {
        self.inner.update_transfer_state(transfer_id, state).await
    }

    async fn update_transfer_state_and_unlock_liquidity(
        &self,
        transfer_id: BridgeTransferId,
        state: BridgeTransferState,
        at: BlockNumber,
    ) -> api::Result<()> {
        self.inner.update_transfer_state_and_unlock_liquidity(transfer_id, state, at).await
    }

    async fn get_transfer_state(
        &self,
        transfer_id: BridgeTransferId,
    ) -> api::Result<Option<BridgeTransferState>> {
        self.inner.get_transfer_state(transfer_id).await
    }

    async fn load_pending_transfers(&self) -> api::Result<Vec<BridgeTransfer>> {
        self.inner.load_pending_transfers().await
    }
}
