//! Relay storage implementation in-memory. For testing only.

use super::{StorageApi, api::Result};
use crate::{
    error::StorageError,
    transactions::{PendingTransaction, RelayTransaction, TransactionStatus, TxId},
    types::{CreatableAccount, KeyID, rpc::BundleId},
};
use alloy::{
    consensus::TxEnvelope,
    primitives::{Address, ChainId},
};
use async_trait::async_trait;
use dashmap::{DashMap, Entry};

/// [`StorageApi`] implementation in-memory. Used for testing
#[derive(Debug, Default)]
pub struct InMemoryStorage {
    accounts: DashMap<Address, CreatableAccount>,
    id_to_accounts: DashMap<Address, Vec<Address>>,
    pending_transactions: DashMap<TxId, PendingTransaction>,
    statuses: DashMap<TxId, (ChainId, TransactionStatus)>,
    bundles: DashMap<BundleId, Vec<TxId>>,
    queued_transactions: DashMap<ChainId, Vec<RelayTransaction>>,
}

#[async_trait]
impl StorageApi for InMemoryStorage {
    async fn read_prep(&self, address: &Address) -> Result<Option<CreatableAccount>> {
        Ok(self.accounts.get(address).map(|acc| (*acc).clone()))
    }

    async fn write_prep(&self, account: CreatableAccount) -> Result<()> {
        let prep_address = account.prep.address;
        let keys = account.id_signatures.iter().map(|k| k.id).collect::<Vec<_>>();

        // Store PREPAccount if it does not yet exist
        match self.accounts.entry(prep_address) {
            Entry::Occupied(_) => {
                return Err(StorageError::AccountAlreadyExists(account.prep.address));
            }
            Entry::Vacant(entry) => {
                entry.insert(account);
            }
        }

        // Store ID -> Address[]
        for id in keys {
            self.id_to_accounts.entry(id).or_default().push(prep_address)
        }

        Ok(())
    }

    async fn read_accounts_from_id(&self, id: &KeyID) -> Result<Vec<Address>> {
        Ok(self.id_to_accounts.get(id).map(|acc| acc.value().clone()).unwrap_or_default())
    }

    async fn replace_queued_tx_with_pending(&self, tx: &PendingTransaction) -> Result<()> {
        if let Some(mut queue) = self.queued_transactions.get_mut(&tx.chain_id()) {
            if let Some(idx) = queue.iter().position(|t| t.id == tx.id()) {
                queue.remove(idx);
            }
        }

        self.pending_transactions.insert(tx.id(), tx.clone());
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

    async fn add_bundle_tx(&self, bundle: BundleId, chain_id: ChainId, tx: TxId) -> Result<()> {
        self.statuses.insert(tx, (chain_id, TransactionStatus::InFlight));
        self.bundles.entry(bundle).or_default().push(tx);
        Ok(())
    }

    async fn get_bundle_transactions(&self, bundle: BundleId) -> Result<Vec<TxId>> {
        Ok(self.bundles.get(&bundle).as_deref().cloned().unwrap_or_default())
    }

    async fn write_queued_transaction(&self, tx: &RelayTransaction) -> Result<()> {
        self.queued_transactions.entry(tx.chain_id()).or_default().push(tx.clone());
        Ok(())
    }

    async fn read_queued_transactions(&self, chain_id: u64) -> Result<Vec<RelayTransaction>> {
        Ok(self.queued_transactions.get(&chain_id).as_deref().cloned().unwrap_or_default())
    }
}
