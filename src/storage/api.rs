//! Relay storage api.

use crate::{
    error::StorageError,
    liquidity::ChainAddress,
    transactions::{PendingTransaction, RelayTransaction, TransactionStatus, TxId},
    types::{CreatableAccount, rpc::BundleId},
};
use alloy::{
    consensus::TxEnvelope,
    primitives::{Address, BlockNumber, ChainId, U256},
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt::Debug};

/// Type alias for `Result<T, StorageError>`
pub type Result<T> = core::result::Result<T, StorageError>;

/// Input for [`StorageApi::try_lock_liquidity`].
#[derive(Debug, Serialize, Deserialize)]
pub struct LockLiquidityInput {
    /// Current balance of the asset fetched from provider.
    pub current_balance: U256,
    /// Block number at which the balance was fetched.
    pub balance_at: BlockNumber,
    /// Amount of the asset we are trying to lock.
    pub lock_amount: U256,
}

/// Storage API.
#[async_trait]
pub trait StorageApi: Debug + Send + Sync {
    /// Reads [`CreatableAccount`] from storage.
    async fn read_account(&self, address: &Address) -> Result<Option<CreatableAccount>>;

    /// Writes [`CreatableAccount`] to storage.
    async fn write_account(&self, account: CreatableAccount) -> Result<()>;

    /// Replaces previously queued transaction with a pending transaction.
    async fn replace_queued_tx_with_pending(&self, tx: &PendingTransaction) -> Result<()>;

    /// Removes a queued transaction from storage.
    async fn remove_queued(&self, tx_id: TxId) -> Result<()>;

    /// Pushes a new [`TxEnvelope`] to [`PendingTransaction::sent`].
    async fn add_pending_envelope(&self, tx_id: TxId, envelope: &TxEnvelope) -> Result<()>;

    /// Removes a pending transaction from storage.
    async fn remove_pending_transaction(&self, tx_id: TxId) -> Result<()>;

    /// Reads pending transactions for the given signer and chain id from storage.
    async fn read_pending_transactions(
        &self,
        signer: Address,
        chain_id: u64,
    ) -> Result<Vec<PendingTransaction>>;

    /// Saves a transaction status.
    async fn write_transaction_status(&self, tx: TxId, status: &TransactionStatus) -> Result<()>;

    /// Reads a transaction status.
    async fn read_transaction_status(
        &self,
        tx: TxId,
    ) -> Result<Option<(ChainId, TransactionStatus)>>;

    /// Adds a transaction to a bundle.
    async fn add_bundle_tx(&self, bundle: BundleId, chain_id: ChainId, tx: TxId) -> Result<()>;

    /// Gets all transactions in a bundle.
    async fn get_bundle_transactions(&self, bundle: BundleId) -> Result<Vec<TxId>>;

    /// Writes a queued transaction.
    async fn write_queued_transaction(&self, tx: &RelayTransaction) -> Result<()>;

    /// Reads queued transactions for the given chain.
    async fn read_queued_transactions(&self, chain_id: u64) -> Result<Vec<RelayTransaction>>;

    /// Checks if a verified email exists.
    async fn verified_email_exists(&self, email: &str) -> Result<bool>;

    /// Adds an unverified email to the database.
    async fn add_unverified_email(&self, account: Address, email: &str, token: &str) -> Result<()>;

    /// Verifies an unverified email in the database if the verification code is valid.
    ///
    /// Should remove any other verified emails for the same account address.
    ///
    /// Returns true if the email was verified successfully.
    async fn verify_email(&self, account: Address, email: &str, token: &str) -> Result<bool>;

    /// Pings the database, checking if the connection is alive.
    async fn ping(&self) -> Result<()>;

    /// Attempts to lock liquidity for the given assets.
    async fn try_lock_liquidity(
        &self,
        assets: HashMap<ChainAddress, LockLiquidityInput>,
    ) -> Result<()>;

    /// Unlocks liquidity for the given asset.
    async fn unlock_liquidity(
        &self,
        asset: ChainAddress,
        amount: U256,
        at: BlockNumber,
    ) -> Result<()>;

    /// Gets total locked liquidity for the given asset.
    async fn get_total_locked_at(&self, asset: ChainAddress, at: BlockNumber) -> Result<U256>;

    /// Removes unlocked entries up until the given block number and subtracts them from the total
    /// locked amount.
    async fn remove_unlocked_entries(&self, chain_id: ChainId, until: BlockNumber) -> Result<()>;
}
