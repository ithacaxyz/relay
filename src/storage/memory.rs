//! Relay storage implementation in-memory. For testing only.

use super::{
    StorageApi,
    api::{OnrampContactInfo, OnrampVerificationStatus, Result},
};
use crate::{
    error::StorageError,
    liquidity::{
        ChainAddress,
        bridge::{BridgeTransfer, BridgeTransferId, BridgeTransferState},
    },
    storage::api::LockLiquidityInput,
    transactions::{
        PendingTransaction, PullGasState, RelayTransaction, TransactionStatus, TxId,
        interop::{BundleStatus, BundleWithStatus, InteropBundle},
    },
    types::{CreatableAccount, SignedCall, rpc::BundleId},
};
use alloy::{
    consensus::{Transaction, TxEnvelope},
    primitives::{Address, B256, BlockNumber, ChainId, U256, map::HashMap},
    rpc::types::TransactionReceipt,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::collections::BTreeMap;
use tokio::sync::RwLock;

/// Key for phone verification storage
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct PhoneKey {
    account: Address,
    phone: String,
}

/// Value for unverified phone storage
#[derive(Debug, Clone)]
struct UnverifiedPhone {
    verification_sid: String,
    attempts: u32,
}

/// Value for verified email storage
#[derive(Debug, Clone)]
struct VerifiedEmail {
    account: Address,
    verified_at: DateTime<Utc>,
}

/// Value for verified phone storage
#[derive(Debug, Clone)]
struct VerifiedPhone {
    account: Address,
    verified_at: DateTime<Utc>,
}

/// [`StorageApi`] implementation in-memory. Used for testing
#[derive(Debug, Default)]
pub struct InMemoryStorage {
    accounts: DashMap<Address, CreatableAccount>,
    pending_transactions: DashMap<TxId, PendingTransaction>,
    statuses: DashMap<TxId, (ChainId, TransactionStatus)>,
    bundles: DashMap<BundleId, Vec<TxId>>,
    queued_transactions: DashMap<ChainId, Vec<RelayTransaction>>,
    unverified_emails: DashMap<(Address, String), String>,
    verified_emails: DashMap<String, VerifiedEmail>,
    unverified_phones: DashMap<PhoneKey, UnverifiedPhone>,
    verified_phones: DashMap<String, VerifiedPhone>,
    pending_bundles: DashMap<BundleId, BundleWithStatus>,
    finished_bundles: DashMap<BundleId, BundleWithStatus>,
    pending_refunds: DashMap<BundleId, DateTime<Utc>>,
    liquidity: RwLock<LiquidityTrackerInner>,
    transfers:
        DashMap<BridgeTransferId, (BridgeTransfer, Option<serde_json::Value>, BridgeTransferState)>,
    pull_gas_transactions: DashMap<B256, (PullGasState, TxEnvelope, Address)>,
    precalls: DashMap<(Address, ChainId, U256), SignedCall>,
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
            self.verified_emails
                .insert(email.to_string(), VerifiedEmail { account, verified_at: Utc::now() });
        }

        Ok(valid)
    }

    async fn verified_phone_exists(&self, phone: &str) -> Result<bool> {
        Ok(self.verified_phones.contains_key(phone))
    }

    async fn add_unverified_phone(
        &self,
        account: Address,
        phone: &str,
        verification_sid: &str,
    ) -> Result<()> {
        let key = PhoneKey { account, phone: phone.to_string() };
        let value = UnverifiedPhone { verification_sid: verification_sid.to_string(), attempts: 0 };
        self.unverified_phones.insert(key, value);
        Ok(())
    }

    async fn mark_phone_verified(&self, account: Address, phone: &str) -> Result<()> {
        let key = PhoneKey { account, phone: phone.to_string() };
        self.unverified_phones.remove(&key);
        self.verified_phones
            .insert(phone.to_string(), VerifiedPhone { account, verified_at: Utc::now() });
        Ok(())
    }

    async fn get_phone_verification_attempts(&self, account: Address, phone: &str) -> Result<u32> {
        let key = PhoneKey { account, phone: phone.to_string() };
        Ok(self.unverified_phones.get(&key).map(|v| v.attempts).unwrap_or(0))
    }

    async fn increment_phone_verification_attempts(
        &self,
        account: Address,
        phone: &str,
    ) -> Result<()> {
        let key = PhoneKey { account, phone: phone.to_string() };
        if let Some(mut entry) = self.unverified_phones.get_mut(&key) {
            entry.attempts += 1;
        }
        Ok(())
    }

    async fn update_phone_verification_sid(
        &self,
        account: Address,
        phone: &str,
        verification_sid: &str,
    ) -> Result<()> {
        let key = PhoneKey { account, phone: phone.to_string() };
        if let Some(mut entry) = self.unverified_phones.get_mut(&key) {
            entry.verification_sid = verification_sid.to_string();
        }
        Ok(())
    }

    async fn get_onramp_verification_status(
        &self,
        account: Address,
    ) -> Result<OnrampVerificationStatus> {
        Ok(OnrampVerificationStatus {
            email: self.verified_emails.iter().find_map(|entry| {
                (entry.value().account == account)
                    .then(|| entry.value().verified_at.timestamp() as u64)
            }),
            phone: self.verified_phones.iter().find_map(|entry| {
                (entry.value().account == account)
                    .then(|| entry.value().verified_at.timestamp() as u64)
            }),
        })
    }

    async fn get_onramp_contact_info(&self, account: Address) -> Result<OnrampContactInfo> {
        Ok(OnrampContactInfo {
            email: self
                .verified_emails
                .iter()
                .find_map(|entry| (entry.value().account == account).then(|| entry.key().clone())),
            phone: self
                .verified_phones
                .iter()
                .find_map(|entry| (entry.value().account == account).then(|| entry.key().clone())),
        })
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

    async fn get_interop_status(&self, bundle_id: BundleId) -> Result<Option<BundleStatus>> {
        if let Some(bundle) = self.pending_bundles.get(&bundle_id) {
            return Ok(Some(bundle.status));
        }

        if let Some(bundle) = self.finished_bundles.get(&bundle_id) {
            return Ok(Some(bundle.status));
        }

        Ok(None)
    }

    async fn get_finished_interop_bundle(
        &self,
        bundle_id: BundleId,
    ) -> Result<Option<BundleWithStatus>> {
        Ok(self.finished_bundles.get(&bundle_id).map(|v| v.clone()))
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

    async fn lock_liquidity_for_bundle(
        &self,
        assets: HashMap<ChainAddress, LockLiquidityInput>,
        bundle_id: BundleId,
        status: BundleStatus,
    ) -> Result<()> {
        self.liquidity.write().await.try_lock_liquidity(assets).await?;
        self.pending_bundles
            .get_mut(&bundle_id)
            .ok_or_else(|| eyre::eyre!("Bundle not found"))?
            .status = status;
        Ok(())
    }

    async fn unlock_bundle_liquidity(
        &self,
        bundle: &InteropBundle,
        receipts: HashMap<TxId, TransactionReceipt>,
        status: BundleStatus,
    ) -> Result<()> {
        for transfer in &bundle.asset_transfers {
            let block =
                receipts.get(&transfer.tx_id).and_then(|r| r.block_number).unwrap_or_default();
            self.liquidity.write().await.unlock_liquidity(
                (transfer.chain_id, transfer.asset_address),
                transfer.amount,
                block,
            );
        }

        self.pending_bundles
            .get_mut(&bundle.id)
            .ok_or_else(|| eyre::eyre!("Bundle not found"))?
            .status = status;

        Ok(())
    }

    async fn get_total_locked_at(&self, asset: ChainAddress, at: BlockNumber) -> Result<U256> {
        Ok(self.liquidity.read().await.get_total_locked_at(asset, at))
    }

    async fn prune_unlocked_entries(&self, chain_id: ChainId, until: BlockNumber) -> Result<()> {
        let mut lock = self.liquidity.write().await;
        let LiquidityTrackerInner { locked_liquidity, pending_unlocks } = &mut *lock;
        for (asset, unlocks) in pending_unlocks {
            if asset.0 == chain_id {
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

    async fn lock_liquidity_for_bridge(
        &self,
        transfer: &BridgeTransfer,
        input: LockLiquidityInput,
    ) -> Result<()> {
        // First try to lock the liquidity
        self.liquidity
            .write()
            .await
            .try_lock_liquidity(HashMap::from_iter([(transfer.from, input)]))
            .await?;
        self.transfers.insert(transfer.id, (transfer.clone(), None, BridgeTransferState::Pending));

        Ok(())
    }

    async fn get_total_locked_liquidity(&self) -> Result<HashMap<ChainAddress, U256>> {
        Ok(self.liquidity.read().await.locked_liquidity.clone())
    }

    async fn get_total_pending_unlocks(&self) -> Result<HashMap<ChainAddress, U256>> {
        Ok(self
            .liquidity
            .read()
            .await
            .pending_unlocks
            .iter()
            .map(|(address, amounts)| (*address, amounts.values().sum()))
            .collect())
    }

    async fn update_transfer_bridge_data(
        &self,
        transfer_id: BridgeTransferId,
        data: &serde_json::Value,
    ) -> Result<()> {
        if let Some(mut transfer_data) = self.transfers.get_mut(&transfer_id) {
            transfer_data.1 = Some(data.clone());
            Ok(())
        } else {
            Err(eyre::eyre!("transfer not found").into())
        }
    }

    async fn get_transfer_bridge_data(
        &self,
        transfer_id: BridgeTransferId,
    ) -> Result<Option<serde_json::Value>> {
        if let Some(transfer_data) = self.transfers.get(&transfer_id) {
            Ok(transfer_data.1.clone())
        } else {
            Err(eyre::eyre!("transfer not found").into())
        }
    }

    async fn update_transfer_state(
        &self,
        transfer_id: BridgeTransferId,
        state: BridgeTransferState,
    ) -> Result<()> {
        if let Some(mut transfer_data) = self.transfers.get_mut(&transfer_id) {
            transfer_data.2 = state;
            Ok(())
        } else {
            Err(eyre::eyre!("transfer not found").into())
        }
    }

    async fn update_transfer_state_and_unlock_liquidity(
        &self,
        transfer_id: BridgeTransferId,
        state: BridgeTransferState,
        at: BlockNumber,
    ) -> Result<()> {
        let transfer = self
            .transfers
            .get(&transfer_id)
            .ok_or_else(|| eyre::eyre!("transfer not found"))?
            .0
            .clone();

        // Update the state
        self.update_transfer_state(transfer_id, state).await?;

        // Unlock liquidity
        self.liquidity.write().await.unlock_liquidity(transfer.from, transfer.amount, at);

        Ok(())
    }

    async fn get_transfer_state(
        &self,
        transfer_id: BridgeTransferId,
    ) -> Result<Option<BridgeTransferState>> {
        if let Some(transfer_data) = self.transfers.get(&transfer_id) {
            Ok(Some(transfer_data.2))
        } else {
            Ok(None)
        }
    }

    async fn load_pending_transfers(&self) -> Result<Vec<BridgeTransfer>> {
        let mut transfers = Vec::new();

        for entry in self.transfers.iter() {
            let (transfer, _, state) = entry.value();
            match state {
                BridgeTransferState::Pending | BridgeTransferState::Sent(_) => {
                    transfers.push(transfer.clone());
                }
                _ => {}
            }
        }

        transfers.sort_by_key(|t| t.id);
        Ok(transfers)
    }

    async fn lock_liquidity_for_pull_gas(
        &self,
        transaction: &TxEnvelope,
        signer: Address,
        input: LockLiquidityInput,
    ) -> Result<()> {
        let chain_id = transaction.chain_id().unwrap_or(0);
        self.liquidity
            .write()
            .await
            .try_lock_liquidity(HashMap::from_iter([((chain_id, Address::ZERO), input)]))
            .await?;

        self.pull_gas_transactions
            .insert(*transaction.tx_hash(), (PullGasState::Pending, transaction.clone(), signer));

        Ok(())
    }

    async fn update_pull_gas_and_unlock_liquidity(
        &self,
        tx_hash: B256,
        chain_id: ChainId,
        amount: U256,
        state: PullGasState,
        at: BlockNumber,
    ) -> Result<()> {
        if let Some(mut entry) = self.pull_gas_transactions.get_mut(&tx_hash) {
            entry.0 = state;
        }

        self.liquidity.write().await.unlock_liquidity((chain_id, Address::ZERO), amount, at);

        Ok(())
    }

    async fn load_pending_pull_gas_transactions(
        &self,
        signer: Address,
        chain_id: ChainId,
    ) -> Result<Vec<TxEnvelope>> {
        let mut pending_transactions = Vec::new();
        for entry in self.pull_gas_transactions.iter() {
            let (state, transaction, tx_signer) = entry.value();

            let tx_chain_id = transaction.chain_id().unwrap_or(0);

            if *state == PullGasState::Pending && *tx_signer == signer && tx_chain_id == chain_id {
                pending_transactions.push(transaction.clone());
            }
        }

        Ok(pending_transactions)
    }

    async fn store_precall(&self, chain_id: ChainId, call: SignedCall) -> Result<()> {
        self.precalls.insert((call.eoa, chain_id, call.nonce), call);
        Ok(())
    }

    async fn read_precalls_for_eoa(
        &self,
        chain_id: ChainId,
        eoa: Address,
    ) -> Result<Vec<SignedCall>> {
        let mut precalls = Vec::new();
        for entry in self.precalls.iter() {
            if entry.key().0 == eoa && entry.key().1 == chain_id {
                precalls.push(entry.value().clone());
            }
        }
        Ok(precalls)
    }

    async fn remove_precall(&self, chain_id: ChainId, eoa: Address, nonce: U256) -> Result<()> {
        self.precalls.remove(&(eoa, chain_id, nonce));
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
            let locked = self.get_total_locked_at(*asset, input.block_number);
            input.lock_amount + locked > input.current_balance
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
