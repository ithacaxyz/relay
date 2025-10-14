//! Relay storage

mod api;
pub use crate::transactions::interop::{BundleStatus, BundleWithStatus, InteropBundle};
use alloy::{
    primitives::{BlockNumber, U256},
    rpc::types::TransactionReceipt,
};
pub use api::{BundleHistoryEntry, LockLiquidityInput, OnrampContactInfo, StorageApi};

mod memory;
mod pg;

use crate::{
    liquidity::{
        ChainAddress,
        bridge::{BridgeTransfer, BridgeTransferId, BridgeTransferState},
    },
    storage::api::OnrampVerificationStatus,
    transactions::{PendingTransaction, PullGasState, RelayTransaction, TransactionStatus, TxId},
    types::{CreatableAccount, HistoricalPrice, HistoricalPriceKey, SignedCall, rpc::BundleId},
};
use alloy::{
    consensus::TxEnvelope,
    primitives::{Address, B256, ChainId, map::HashMap},
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

    async fn read_transaction_statuses(
        &self,
        tx_ids: &[TxId],
    ) -> api::Result<Vec<Option<(ChainId, TransactionStatus)>>> {
        self.inner.read_transaction_statuses(tx_ids).await
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

    async fn verified_phone_exists(&self, phone: &str) -> api::Result<bool> {
        self.inner.verified_phone_exists(phone).await
    }

    async fn add_unverified_phone(
        &self,
        account: Address,
        phone: &str,
        verification_sid: &str,
    ) -> api::Result<()> {
        self.inner.add_unverified_phone(account, phone, verification_sid).await
    }

    async fn mark_phone_verified(&self, account: Address, phone: &str) -> api::Result<()> {
        self.inner.mark_phone_verified(account, phone).await
    }

    async fn get_phone_verification_attempts(
        &self,
        account: Address,
        phone: &str,
    ) -> api::Result<u32> {
        self.inner.get_phone_verification_attempts(account, phone).await
    }

    async fn increment_phone_verification_attempts(
        &self,
        account: Address,
        phone: &str,
    ) -> api::Result<()> {
        self.inner.increment_phone_verification_attempts(account, phone).await
    }

    async fn update_phone_verification_sid(
        &self,
        account: Address,
        phone: &str,
        verification_sid: &str,
    ) -> api::Result<()> {
        self.inner.update_phone_verification_sid(account, phone, verification_sid).await
    }

    async fn get_onramp_verification_status(
        &self,
        account: Address,
    ) -> api::Result<OnrampVerificationStatus> {
        self.inner.get_onramp_verification_status(account).await
    }

    async fn get_onramp_contact_info(&self, account: Address) -> api::Result<OnrampContactInfo> {
        self.inner.get_onramp_contact_info(account).await
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

    async fn get_interop_status(&self, bundle_id: BundleId) -> api::Result<Option<BundleStatus>> {
        self.inner.get_interop_status(bundle_id).await
    }

    async fn get_finished_interop_bundle(
        &self,
        bundle_id: BundleId,
    ) -> api::Result<Option<BundleWithStatus>> {
        self.inner.get_finished_interop_bundle(bundle_id).await
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

    async fn get_total_locked_liquidity(&self) -> api::Result<HashMap<ChainAddress, U256>> {
        self.inner.get_total_locked_liquidity().await
    }

    async fn get_total_pending_unlocks(&self) -> api::Result<HashMap<ChainAddress, U256>> {
        self.inner.get_total_pending_unlocks().await
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

    async fn lock_liquidity_for_pull_gas(
        &self,
        transaction: &TxEnvelope,
        signer: Address,
        input: LockLiquidityInput,
    ) -> api::Result<()> {
        self.inner.lock_liquidity_for_pull_gas(transaction, signer, input).await
    }

    async fn update_pull_gas_and_unlock_liquidity(
        &self,
        tx_hash: B256,
        chain_id: ChainId,
        amount: U256,
        state: PullGasState,
        at: BlockNumber,
    ) -> api::Result<()> {
        self.inner.update_pull_gas_and_unlock_liquidity(tx_hash, chain_id, amount, state, at).await
    }

    async fn load_pending_pull_gas_transactions(
        &self,
        signer: Address,
        chain_id: ChainId,
    ) -> api::Result<Vec<TxEnvelope>> {
        self.inner.load_pending_pull_gas_transactions(signer, chain_id).await
    }

    async fn store_precall(&self, chain_id: ChainId, call: SignedCall) -> api::Result<()> {
        self.inner.store_precall(chain_id, call).await
    }

    async fn read_precalls_for_eoa(
        &self,
        chain_id: ChainId,
        eoa: Address,
    ) -> api::Result<Vec<SignedCall>> {
        self.inner.read_precalls_for_eoa(chain_id, eoa).await
    }

    async fn remove_precall(
        &self,
        chain_id: ChainId,
        eoa: Address,
        nonce: U256,
    ) -> api::Result<()> {
        self.inner.remove_precall(chain_id, eoa, nonce).await
    }

    async fn get_bundles_by_address(
        &self,
        address: Address,
        limit: u64,
        offset: u64,
        sort_desc: bool,
    ) -> api::Result<Vec<api::BundleHistoryEntry>> {
        self.inner.get_bundles_by_address(address, limit, offset, sort_desc).await
    }

    async fn get_bundle_count_by_address(&self, address: Address) -> api::Result<u64> {
        self.inner.get_bundle_count_by_address(address).await
    }

    async fn store_historical_usd_prices(&self, prices: Vec<HistoricalPrice>) -> api::Result<()> {
        self.inner.store_historical_usd_prices(prices).await
    }

    async fn read_historical_usd_prices(
        &self,
        queries: Vec<HistoricalPriceKey>,
    ) -> api::Result<HashMap<HistoricalPriceKey, (u64, f64)>> {
        self.inner.read_historical_usd_prices(queries).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AssetUid;

    async fn get_test_storage() -> RelayStorage {
        if let Ok(db_url) = std::env::var("DATABASE_URL") {
            let pool = PgPool::connect(&db_url).await.expect("Failed to connect to PostgreSQL");
            sqlx::migrate!().run(&pool).await.expect("Failed to run migrations");
            RelayStorage::pg(pool)
        } else {
            RelayStorage::in_memory()
        }
    }

    #[tokio::test]
    async fn test_historical_price_storage() {
        let storage = get_test_storage().await;

        let eth_uid = AssetUid::new("eth".to_string());
        let usdc_uid = AssetUid::new("usdc".to_string());

        // Store prices at specific timestamps
        let prices = vec![
            HistoricalPrice { asset_uid: eth_uid.clone(), timestamp: 1000, usd_price: 2500.0 },
            HistoricalPrice { asset_uid: eth_uid.clone(), timestamp: 1600, usd_price: 5600.0 },
            HistoricalPrice { asset_uid: usdc_uid.clone(), timestamp: 1000, usd_price: 1.0 },
        ];

        storage.store_historical_usd_prices(prices).await.unwrap();

        // Test queries: (query_timestamp, expected_result)
        let test_cases = vec![
            (1000, Some((1000, 2500.0))), // Exact match
            (1200, Some((1000, 2500.0))), // Approximate: 1000 is 200s away, 1600 is 400s away
            (1700, Some((1600, 5600.0))), // Approximate: 1600 is 100s away
            (5000, None),                 // No match: outside ±5 minute window
        ];

        for (query_ts, expected) in test_cases {
            let results = storage
                .read_historical_usd_prices(vec![HistoricalPriceKey {
                    asset_uid: eth_uid.clone(),
                    timestamp: query_ts,
                }])
                .await
                .unwrap();

            match expected {
                Some((expected_ts, expected_price)) => {
                    assert_eq!(results.len(), 1);
                    let (ts, price) = results
                        .get(&HistoricalPriceKey {
                            asset_uid: eth_uid.clone(),
                            timestamp: query_ts,
                        })
                        .unwrap();
                    assert_eq!(*ts, expected_ts);
                    assert_eq!(*price, expected_price);
                }
                None => {
                    assert_eq!(results.len(), 0);
                }
            }
        }
    }
}
