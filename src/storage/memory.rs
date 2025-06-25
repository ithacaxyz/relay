//! Relay storage implementation in-memory. For testing only.

use super::{StorageApi, api::Result};
use crate::{
    error::StorageError,
    liquidity::ChainAddress,
    storage::api::LockLiquidityInput,
    transactions::{PendingTransaction, RelayTransaction, TransactionStatus, TxId},
    types::{CreatableAccount, rpc::BundleId},
};
use alloy::{
    consensus::TxEnvelope,
    primitives::{Address, BlockNumber, ChainId, U256},
};
use async_trait::async_trait;
use dashmap::DashMap;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};
use tokio::sync::RwLock;

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
    liquidity: Arc<RwLock<LiquidityTrackerInner>>,
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

    async fn try_lock_liquidity(
        &self,
        assets: HashMap<ChainAddress, LockLiquidityInput>,
    ) -> Result<()> {
        self.liquidity.write().await.try_lock_liquidity(assets).await
    }

    async fn unlock_liquidity(
        &self,
        asset: ChainAddress,
        amount: U256,
        at: BlockNumber,
    ) -> Result<()> {
        self.liquidity.write().await.unlock_liquidity(asset, amount, at);

        Ok(())
    }

    async fn get_total_locked_at(&self, asset: ChainAddress, at: BlockNumber) -> Result<U256> {
        Ok(self.liquidity.read().await.get_total_locked_at(asset, at))
    }

    async fn remove_unlocked_entries(&self, chain_id: ChainId, until: BlockNumber) -> Result<()> {
        let mut lock = self.liquidity.write().await;
        let LiquidityTrackerInner { locked_liquidity, pending_unlocks } = &mut *lock;
        for (asset, unlocks) in pending_unlocks {
            if asset.0 == chain_id {
                // Keep 10 blocks of pending unlocks
                let to_keep = unlocks.split_off(&until);
                let to_remove = core::mem::replace(unlocks, to_keep);

                // Remove everything else from the locked mapping
                for (_, unlock) in to_remove {
                    locked_liquidity.entry(*asset).and_modify(|amount| {
                        *amount = amount.saturating_sub(unlock);
                    });
                }
            }
        }

        Ok(())
    }
}

/// An In-memory liquidity tracker.
#[derive(Debug, Default)]
struct LiquidityTrackerInner {
    /// Assets that are about to be pulled from us, indexed by chain and asset address.
    ///
    /// Those correspond to pending cross-chain intents that are not yet confirmed.
    locked_liquidity: HashMap<ChainAddress, U256>,
    /// Liquidity amounts that are unlocked at certain block numbers.
    ///
    /// Those correspond to blocks when we've sent funds to users.
    pending_unlocks: HashMap<ChainAddress, BTreeMap<BlockNumber, U256>>,
}

impl LiquidityTrackerInner {
    /// Does a pessimistic estimate of our balance in the given asset, subtracting all of the locked
    /// balances and adding all of the unlocked ones.
    fn get_total_locked_at(&self, asset: ChainAddress, at: BlockNumber) -> U256 {
        let locked = self.locked_liquidity.get(&asset).copied().unwrap_or_default();
        let unlocked = self
            .pending_unlocks
            .get(&asset)
            .map(|unlocks| unlocks.range(..=at).map(|(_, amount)| *amount).sum::<U256>())
            .unwrap_or_default();

        locked.saturating_sub(unlocked)
    }

    /// Attempts to lock liquidity by firstly making sure that we have enough funds for it.
    async fn try_lock_liquidity(
        &mut self,
        assets: HashMap<ChainAddress, LockLiquidityInput>,
    ) -> Result<()> {
        // Make sure that we have enough funds for all transfers
        if assets.iter().any(|(asset, input)| {
            let locked = self.get_total_locked_at(*asset, input.balance_at);
            input.lock_amount + locked < input.current_balance
        }) {
            return Err(StorageError::CantLockLiquidity);
        }

        // Lock liquidity
        for (asset, input) in assets {
            *self.locked_liquidity.entry(asset).or_default() += input.lock_amount;
        }

        Ok(())
    }

    /// Unlocks liquidity by adding it to the pending unlocks mapping. This should be called once
    /// bundle is confirmed.
    fn unlock_liquidity(&mut self, asset: ChainAddress, amount: U256, at: BlockNumber) {
        *self.pending_unlocks.entry(asset).or_default().entry(at).or_default() += amount;
    }
}
