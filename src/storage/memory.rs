//! Relay storage implementation in-memory. For testing only.

use super::{InteropTxType, StorageApi, api::Result};
use crate::{
    transactions::{
        PendingTransaction, RelayTransaction, TransactionStatus, TxId,
        interop::{BundleStatus, BundleWithStatus, InteropBundle},
    },
    types::{CreatableAccount, rpc::BundleId},
};
use alloy::{
    consensus::TxEnvelope,
    primitives::{Address, ChainId},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dashmap::DashMap;

/// [`StorageApi`] implementation in-memory. Used for testing
#[derive(Debug, Default)]
pub struct InMemoryStorage {
    accounts: DashMap<Address, CreatableAccount>,
    pending_transactions: DashMap<TxId, PendingTransaction>,
    statuses: DashMap<TxId, (ChainId, TransactionStatus)>,
    bundles: DashMap<BundleId, Vec<TxId>>,
    queued_transactions: DashMap<ChainId, Vec<RelayTransaction>>,
    unverified_emails: DashMap<(Address, String), String>,
    verified_emails: DashMap<String, Address>,
    pending_bundles: DashMap<BundleId, BundleWithStatus>,
    finished_bundles: DashMap<BundleId, BundleWithStatus>,
    pending_refunds: DashMap<BundleId, DateTime<Utc>>,
}

#[async_trait]
impl StorageApi for InMemoryStorage {
    async fn read_account(&self, address: &Address) -> Result<Option<CreatableAccount>> {
        Ok(self.accounts.get(address).map(|acc| (*acc).clone()))
    }

    async fn write_account(&self, account: CreatableAccount) -> Result<()> {
        self.accounts.insert(account.address, account);
        Ok(())
    }

    async fn replace_queued_tx_with_pending(&self, tx: &PendingTransaction) -> Result<()> {
        self.remove_queued(tx.id()).await?;
        self.pending_transactions.insert(tx.id(), tx.clone());
        Ok(())
    }

    async fn remove_queued(&self, tx_id: TxId) -> Result<()> {
        for mut queue in self.queued_transactions.iter_mut() {
            if let Some(idx) = queue.iter().position(|t| t.id == tx_id) {
                queue.remove(idx);
            }
        }

        Ok(())
    }

    async fn add_pending_envelope(&self, tx_id: TxId, envelope: &TxEnvelope) -> Result<()> {
        if let Some(mut tx) = self.pending_transactions.get_mut(&tx_id) {
            tx.sent.push(envelope.clone());
        }
        Ok(())
    }

    async fn remove_pending_transaction(&self, tx_id: TxId) -> Result<()> {
        self.pending_transactions.remove(&tx_id);
        Ok(())
    }

    async fn read_pending_transactions(
        &self,
        signer: Address,
        chain_id: u64,
    ) -> Result<Vec<PendingTransaction>> {
        let mut txs = Vec::new();
        for item in self.pending_transactions.iter() {
            let tx = item.value();
            if tx.signer == signer && tx.chain_id() == chain_id {
                txs.push(tx.clone());
            }
        }

        Ok(txs)
    }

    async fn write_transaction_status(&self, tx: TxId, status: &TransactionStatus) -> Result<()> {
        self.statuses.entry(tx).and_modify(|tx| tx.1 = status.clone());
        Ok(())
    }

    async fn read_transaction_status(
        &self,
        tx: TxId,
    ) -> Result<Option<(ChainId, TransactionStatus)>> {
        Ok(self.statuses.get(&tx).as_deref().cloned())
    }

    async fn add_bundle_tx(&self, bundle: BundleId, tx: TxId) -> Result<()> {
        self.bundles.entry(bundle).or_default().push(tx);
        Ok(())
    }

    async fn get_bundle_transactions(&self, bundle: BundleId) -> Result<Vec<TxId>> {
        Ok(self.bundles.get(&bundle).as_deref().cloned().unwrap_or_default())
    }

    async fn queue_transaction(&self, tx: &RelayTransaction) -> Result<()> {
        self.statuses.insert(tx.id, (tx.chain_id(), TransactionStatus::InFlight));
        self.queued_transactions.entry(tx.chain_id()).or_default().push(tx.clone());
        Ok(())
    }

    async fn read_queued_transactions(&self, chain_id: u64) -> Result<Vec<RelayTransaction>> {
        Ok(self.queued_transactions.get(&chain_id).as_deref().cloned().unwrap_or_default())
    }

    async fn verified_email_exists(&self, email: &str) -> Result<bool> {
        Ok(self.verified_emails.contains_key(email))
    }

    async fn add_unverified_email(&self, account: Address, email: &str, token: &str) -> Result<()> {
        self.unverified_emails.insert((account, email.to_string()), token.to_string());

        Ok(())
    }

    async fn verify_email(&self, account: Address, email: &str, token: &str) -> Result<bool> {
        let key = (account, email.to_string());
        let valid = self
            .unverified_emails
            .get(&key)
            .map(|expected_token| token == *expected_token)
            .unwrap_or_default();

        if valid {
            self.unverified_emails.remove(&key);
            self.verified_emails.insert(email.to_string(), account);
        }

        Ok(valid)
    }

    async fn ping(&self) -> Result<()> {
        Ok(())
    }

    async fn store_pending_bundle(
        &self,
        bundle: &InteropBundle,
        status: BundleStatus,
    ) -> Result<()> {
        self.pending_bundles.insert(bundle.id, BundleWithStatus { bundle: bundle.clone(), status });
        Ok(())
    }

    async fn update_pending_bundle_status(
        &self,
        bundle_id: BundleId,
        status: BundleStatus,
    ) -> Result<()> {
        if let Some(mut entry) = self.pending_bundles.get_mut(&bundle_id) {
            entry.status = status;
        }
        Ok(())
    }

    async fn get_pending_bundles(&self) -> Result<Vec<BundleWithStatus>> {
        // Return all bundles
        Ok(self.pending_bundles.iter().map(|entry| entry.value().clone()).collect())
    }

    async fn get_pending_bundle(&self, bundle_id: BundleId) -> Result<Option<BundleWithStatus>> {
        Ok(self.pending_bundles.get(&bundle_id).map(|entry| entry.value().clone()))
    }

    async fn queue_bundle_transactions(
        &self,
        bundle: &InteropBundle,
        status: BundleStatus,
        tx_type: InteropTxType,
    ) -> Result<()> {
        // Queue the appropriate transactions
        for tx in bundle.transactions(tx_type) {
            self.queue_transaction(tx).await?;
        }

        // Only update the status, don't store the bundle
        self.update_pending_bundle_status(bundle.id, status).await?;

        Ok(())
    }

    async fn update_bundle_and_queue_transactions(
        &self,
        bundle: &InteropBundle,
        status: BundleStatus,
        transactions: &[RelayTransaction],
    ) -> Result<()> {
        // First store the bundle with the new status
        self.store_pending_bundle(bundle, status).await?;

        // Then queue the specific transactions provided
        for relay_tx in transactions {
            self.queue_transaction(relay_tx).await?;
        }

        Ok(())
    }

    async fn move_bundle_to_finished(&self, bundle_id: BundleId) -> Result<()> {
        if let Some((_, bundle_with_status)) = self.pending_bundles.remove(&bundle_id) {
            self.finished_bundles.insert(bundle_id, bundle_with_status);
            Ok(())
        } else {
            Err(eyre::eyre!("Bundle not found: {:?}", bundle_id).into())
        }
    }

    async fn store_pending_refund(
        &self,
        bundle_id: BundleId,
        refund_timestamp: DateTime<Utc>,
        new_status: BundleStatus,
    ) -> Result<()> {
        self.pending_refunds.insert(bundle_id, refund_timestamp);

        if let Some(mut entry) = self.pending_bundles.get_mut(&bundle_id) {
            entry.status = new_status;
        }

        Ok(())
    }

    async fn get_pending_refunds_ready(
        &self,
        current_time: DateTime<Utc>,
    ) -> Result<Vec<(BundleId, DateTime<Utc>)>> {
        Ok(self
            .pending_refunds
            .iter()
            .filter(|entry| *entry.value() <= current_time)
            .map(|entry| (*entry.key(), *entry.value()))
            .collect())
    }

    async fn remove_processed_refund(&self, bundle_id: BundleId) -> Result<()> {
        self.pending_refunds.remove(&bundle_id);
        Ok(())
    }

    async fn mark_refund_ready(&self, bundle_id: BundleId, new_status: BundleStatus) -> Result<()> {
        // Update bundle status
        if let Some(mut bundle) = self.pending_bundles.get_mut(&bundle_id) {
            bundle.status = new_status;
        }

        // Remove from pending refunds
        self.remove_processed_refund(bundle_id).await?;

        Ok(())
    }
}
