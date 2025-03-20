//! Relay storage implementation in-memory. For testing only.

use super::{StorageApi, StorageError, api::Result};
use crate::{
    transactions::{PendingTransaction, TransactionStatus},
    types::{PREPAccount, rpc::BundleId},
};
use alloy::primitives::Address;
use async_trait::async_trait;
use dashmap::{DashMap, Entry};

/// [`StorageApi`] implementation in-memory. Used for testing
#[derive(Debug, Default)]
pub struct InMemoryStorage {
    accounts: DashMap<Address, PREPAccount>,
    pending_transactions: DashMap<BundleId, PendingTransaction>,
    statuses: DashMap<BundleId, TransactionStatus>,
}

#[async_trait]
impl StorageApi for InMemoryStorage {
    async fn read_prep(&self, address: &Address) -> Result<Option<PREPAccount>> {
        Ok(self.accounts.get(address).map(|acc| (*acc).clone()))
    }

    async fn write_prep(&self, account: &PREPAccount) -> Result<()> {
        match self.accounts.entry(account.address) {
            Entry::Occupied(_) => Err(StorageError::AccountAlreadyExists(account.address)),
            Entry::Vacant(entry) => {
                entry.insert(account.clone());
                Ok(())
            }
        }
    }

    async fn write_pending_transaction(&self, tx: &PendingTransaction) -> Result<()> {
        self.pending_transactions.insert(tx.id(), tx.clone());
        Ok(())
    }

    async fn remove_pending_transaction(&self, tx_id: BundleId) -> Result<()> {
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

    async fn write_transaction_status(
        &self,
        tx: BundleId,
        status: &TransactionStatus,
    ) -> Result<()> {
        self.statuses.insert(tx, status.clone());
        Ok(())
    }

    async fn read_transaction_status(&self, tx: BundleId) -> Result<Option<TransactionStatus>> {
        Ok(self.statuses.get(&tx).as_deref().cloned())
    }
}
