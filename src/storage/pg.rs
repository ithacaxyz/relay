//! Relay storage implementation using a PostgreSQL database.

use super::{
    StorageApi,
    api::{BundleHistoryEntry, OnrampContactInfo, OnrampVerificationStatus, Result},
};

/// Whether to store full transaction data in the txs.tx column
#[derive(Debug, Clone, Copy)]
enum StoreTxData {
    /// Store full transaction data (for single-chain bundles)
    Yes,
    /// Don't store transaction data to avoid duplication (for interop bundles where data is in
    /// bundle_data)
    No,
}
use crate::{
    error::StorageError,
    liquidity::{
        ChainAddress,
        bridge::{BridgeTransfer, BridgeTransferId, BridgeTransferState},
    },
    storage::api::LockLiquidityInput,
    transactions::{
        PendingTransaction, PullGasState, RelayTransaction, RelayTransactionKind,
        TransactionStatus, TxId,
        interop::{BundleStatus, BundleWithStatus, InteropBundle},
    },
    types::{
        AssetUid, CreatableAccount, HistoricalPrice, HistoricalPriceKey, SignedCall, rpc::BundleId,
    },
};
use alloy::{
    consensus::{Transaction, TxEnvelope},
    hex,
    primitives::{Address, B256, BlockNumber, ChainId, TxHash, U256, map::HashMap},
    rpc::types::TransactionReceipt,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use eyre::eyre;
use sqlx::{PgPool, Postgres, Row, types::BigDecimal};
use tracing::{error, instrument};

/// PostgreSQL storage implementation.
#[derive(Debug)]
pub struct PgStorage {
    pool: PgPool,
}

impl PgStorage {
    /// Creates a new PostgreSQL storage instance.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Queue a single transaction within an existing database transaction
    async fn queue_transaction_with(
        &self,
        relay_tx: &RelayTransaction,
        store_tx_data: StoreTxData,
        tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    ) -> Result<()> {
        // Insert transaction into txs table
        let tx_value = match store_tx_data {
            StoreTxData::Yes => Some(serde_json::to_value(relay_tx)?),
            StoreTxData::No => None,
        };

        sqlx::query!(
            "insert into txs (tx_id, chain_id, tx) values ($1, $2, $3)",
            relay_tx.id.as_slice(),
            relay_tx.chain_id() as i64, // yikes..
            tx_value
        )
        .execute(&mut **tx)
        .await
        .map_err(eyre::Error::from)?;

        sqlx::query!(
            r#"
            INSERT INTO queued_txs (tx_id, chain_id, tx)
            VALUES ($1, $2, $3)
            ON CONFLICT (tx_id) DO NOTHING
            "#,
            relay_tx.id.as_slice(),
            relay_tx.chain_id() as i64,
            serde_json::to_value(relay_tx)?
        )
        .execute(&mut **tx)
        .await
        .map_err(eyre::Error::from)?;

        Ok(())
    }

    /// Update pending bundle status within an existing database transaction
    async fn update_pending_bundle_status_with(
        &self,
        bundle_id: BundleId,
        status: BundleStatus,
        tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE pending_bundles
            SET status = $2, updated_at = NOW()
            WHERE bundle_id = $1
            "#,
            bundle_id.as_slice(),
            status as _
        )
        .execute(&mut **tx)
        .await
        .map_err(eyre::Error::from)?;

        Ok(())
    }

    /// Remove processed refund within an existing database transaction
    async fn remove_processed_refund_with(
        &self,
        bundle_id: BundleId,
        tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            DELETE FROM pending_refunds
            WHERE bundle_id = $1
            "#,
            bundle_id.as_slice()
        )
        .execute(&mut **tx)
        .await
        .map_err(eyre::Error::from)?;

        Ok(())
    }

    async fn try_lock_liquidity_with(
        &self,
        assets: HashMap<ChainAddress, LockLiquidityInput>,
        tx: &mut sqlx::Transaction<'static, Postgres>,
    ) -> Result<()> {
        let (chain_ids, asset_addresses): (Vec<_>, Vec<_>) = assets
            .iter()
            .map(|((chain, asset), _)| (*chain as i64, asset.as_slice().to_vec()))
            .unzip();

        let locked = sqlx::query!(
            "select * from locked_liquidity where (chain_id, asset_address) = ANY(SELECT unnest($1::bigint[]), unnest($2::bytea[]))",
            &chain_ids,
            &asset_addresses
        )
        .fetch_all(&mut **tx)
        .await
        .map_err(eyre::Error::from)?;

        // create rows that don't exist
        for ((chain, asset), _) in assets.iter().filter(|((chain, asset), _)| {
            !locked
                .iter()
                .any(|row| row.chain_id == *chain as i64 && row.asset_address == asset.as_slice())
        }) {
            sqlx::query!(
                "insert into locked_liquidity (chain_id, asset_address, amount) values ($1, $2, $3) on conflict do nothing",
                *chain as i64,
                asset.as_slice(),
                BigDecimal::default(),
            )
            .execute(&mut **tx)
            .await
            .map_err(eyre::Error::from)?;
        }

        // select all locked assets for update
        let locked = sqlx::query!(
            "select * from locked_liquidity where (chain_id, asset_address) = ANY(SELECT unnest($1::bigint[]), unnest($2::bytea[])) for update",
            &chain_ids,
            &asset_addresses
        )
        .fetch_all(&mut **tx)
        .await
        .map_err(eyre::Error::from)?;

        // select all unlocked assets
        let unlocked = sqlx::query!(
            "select * from pending_unlocks where (chain_id, asset_address) = ANY(SELECT unnest($1::bigint[]), unnest($2::bytea[])) for update",
            &chain_ids,
            &asset_addresses
        )
        .fetch_all(&mut **tx)
        .await.map_err(eyre::Error::from)?;

        for ((chain, asset), input) in assets {
            let locked = locked
                .iter()
                .find(|row| row.chain_id == chain as i64 && row.asset_address == asset.as_slice())
                .map(|row| numeric_to_u256(&row.amount))
                .unwrap_or_default();

            let unlocked = unlocked
                .iter()
                .filter(|row| {
                    row.chain_id == chain as i64
                        && row.asset_address == asset.as_slice()
                        && row.block_number <= input.block_number as i64
                })
                .map(|row| numeric_to_u256(&row.amount))
                .sum::<U256>();

            if input.current_balance + unlocked >= locked + input.lock_amount {
                sqlx::query!(
                    "update locked_liquidity set amount = $1 where chain_id = $2 and asset_address = $3",
                    u256_to_numeric(locked + input.lock_amount),
                    chain as i64,
                    asset.as_slice()
                )
                .execute(&mut **tx)
                .await
                .map_err(eyre::Error::from)?;
            } else {
                error!(?locked, ?unlocked, balance=?input.current_balance, lock_amount=?input.lock_amount, ?chain, ?asset, "not enough liquidity");
                return Err(StorageError::CantLockLiquidity);
            }
        }

        Ok(())
    }

    async fn update_transfer_state_with(
        &self,
        transfer_id: BridgeTransferId,
        state: BridgeTransferState,
        tx: &mut sqlx::Transaction<'static, Postgres>,
    ) -> Result<()> {
        let status = match state {
            BridgeTransferState::Pending => BridgeTransferStatus::Pending,
            BridgeTransferState::Sent(_) => BridgeTransferStatus::Sent,
            BridgeTransferState::OutboundFailed => BridgeTransferStatus::OutboundFailed,
            BridgeTransferState::Completed(_) => BridgeTransferStatus::Completed,
            BridgeTransferState::InboundFailed => BridgeTransferStatus::InboundFailed,
        };

        sqlx::query!(
            "update bridge_transfers set status = $1 where transfer_id = $2",
            status as BridgeTransferStatus,
            transfer_id.as_slice(),
        )
        .execute(&mut **tx)
        .await
        .map_err(eyre::Error::from)?;

        if let BridgeTransferState::Sent(block_number) = state {
            sqlx::query!(
                "update bridge_transfers set outbound_block_number = $1 where transfer_id = $2",
                block_number as i64,
                transfer_id.as_slice(),
            )
            .execute(&mut **tx)
            .await
            .map_err(eyre::Error::from)?;
        }

        if let BridgeTransferState::Completed(block_number) = state {
            sqlx::query!(
                "update bridge_transfers set inbound_block_number = $1 where transfer_id = $2",
                block_number as i64,
                transfer_id.as_slice(),
            )
            .execute(&mut **tx)
            .await
            .map_err(eyre::Error::from)?;
        }

        Ok(())
    }

    /// Store a pending bundle within an existing database transaction
    async fn store_pending_bundle_with(
        &self,
        bundle: &InteropBundle,
        status: BundleStatus,
        tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO pending_bundles (bundle_id, status, bundle_data, created_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (bundle_id) DO UPDATE SET
                status = EXCLUDED.status,
                bundle_data = EXCLUDED.bundle_data,
                updated_at = NOW()
            "#,
            bundle.id.as_slice(),
            status as _,
            serde_json::to_value(bundle)?,
        )
        .execute(&mut **tx)
        .await
        .map_err(eyre::Error::from)?;

        Ok(())
    }

    async fn unlock_liquidity_with(
        &self,
        asset: ChainAddress,
        amount: U256,
        at: BlockNumber,
        executor: impl sqlx::Executor<'_, Database = Postgres>,
    ) -> Result<()> {
        sqlx::query!(
            "insert into pending_unlocks (chain_id, asset_address, amount, block_number) values ($1, $2, $3, $4)",
            asset.0 as i64,
            asset.1.as_slice(),
            u256_to_numeric(amount),
            at as i64,
        )
        .execute(executor)
        .await
        .map_err(eyre::Error::from)?;

        Ok(())
    }

    async fn load_transfer_with(
        &self,
        transfer_id: BridgeTransferId,
        executor: impl sqlx::Executor<'_, Database = Postgres>,
    ) -> Result<Option<BridgeTransfer>> {
        let Some(row) = sqlx::query!(
            "select transfer_data from bridge_transfers where transfer_id = $1",
            transfer_id.as_slice()
        )
        .fetch_optional(executor)
        .await
        .map_err(eyre::Error::from)?
        else {
            return Ok(None);
        };

        Ok(Some(serde_json::from_value(row.transfer_data)?))
    }
}

/// This is a wrapper around [`TransactionStatus`] since `sqlx` does not support enums with
/// associated data.
#[derive(Debug, sqlx::Type)]
#[sqlx(type_name = "tx_status", rename_all = "lowercase")]
enum TxStatus {
    InFlight,
    Pending,
    Confirmed,
    Failed,
}

/// Helper macro to parse transaction status from database row.
macro_rules! parse_transaction_status {
    ($row:expr) => {{
        let tx_hash = $row.tx_hash.as_ref().map(|hash| B256::from_slice(hash));
        (|| -> Result<_> {
            Ok((
                $row.chain_id as u64,
                match $row.status {
                    TxStatus::InFlight => TransactionStatus::InFlight,
                    // SAFETY: it should never be possible to have a pending transaction without a
                    // hash in the database
                    TxStatus::Pending => TransactionStatus::Pending(tx_hash.unwrap()),
                    // SAFETY: it should never be possible to have a confirmed transaction without a
                    // receipt in the database
                    TxStatus::Confirmed => TransactionStatus::Confirmed(
                        serde_json::from_value($row.receipt.unwrap()).map_err(eyre::Error::from)?,
                    ),
                    TxStatus::Failed => TransactionStatus::failed(
                        $row.error.unwrap_or_else(|| "transaction failed".to_string()),
                    ),
                },
            ))
        })()
    }};
}

/// This is a wrapper around [`TransferState`] since `sqlx` does not support enums with
/// associated data.
#[derive(Debug, sqlx::Type)]
#[sqlx(type_name = "bridge_transfer_status", rename_all = "snake_case")]
enum BridgeTransferStatus {
    Pending,
    Sent,
    OutboundFailed,
    Completed,
    InboundFailed,
}

struct BridgeTransferRow {
    status: BridgeTransferStatus,
    outbound_block_number: Option<i64>,
    inbound_block_number: Option<i64>,
}

fn numeric_to_u256(value: &BigDecimal) -> U256 {
    value.round(0).into_bigint_and_scale().0.try_into().unwrap()
}

fn u256_to_numeric(value: U256) -> BigDecimal {
    BigDecimal::from_biguint(value.into(), 0)
}

#[async_trait]
impl StorageApi for PgStorage {
    #[instrument(self)]
    async fn read_account(&self, address: &Address) -> Result<Option<CreatableAccount>> {
        let row =
            sqlx::query!(r#"select account from accounts where address = $1"#, address.as_slice())
                .fetch_optional(&self.pool)
                .await
                .map_err(eyre::Error::from)?;

        Ok(row.and_then(|row| serde_json::from_value(row.account).ok()))
    }

    #[instrument(skip_all)]
    async fn write_account(&self, account: CreatableAccount) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(eyre::Error::from)?;
        sqlx::query(
            "insert into accounts (address, account) values ($1, $2)  on conflict (address) do update set account = excluded.account",
        )
        .bind(account.address.as_slice())
        .bind(serde_json::to_value(&account)?)
        .execute(&mut *tx)
        .await
        .map_err(eyre::Error::from)?;

        tx.commit().await.map_err(eyre::Error::from)?;

        Ok(())
    }

    #[instrument(skip_all)]
    async fn replace_queued_tx_with_pending(&self, tx: &PendingTransaction) -> Result<()> {
        let mut db_tx = self.pool.begin().await.map_err(eyre::Error::from)?;

        sqlx::query!("delete from queued_txs where tx_id = $1", tx.tx.id.as_slice())
            .execute(&mut *db_tx)
            .await
            .map_err(eyre::Error::from)?;

        sqlx::query!(
            "insert into pending_txs (chain_id, sender, tx_id, tx, envelopes, sent_at) values ($1, $2, $3, $4, $5, $6)",
            tx.chain_id() as i64, // yikes!
            tx.signer.as_slice(),
            tx.tx.id.as_slice(),
            serde_json::to_value(&tx.tx)?,
            serde_json::to_value(&tx.sent)?,
            tx.sent_at.naive_utc(),
        )
        .execute(&mut *db_tx)
        .await
        .map_err(eyre::Error::from)?;

        db_tx.commit().await.map_err(eyre::Error::from)?;

        Ok(())
    }

    async fn remove_queued(&self, tx_id: TxId) -> Result<()> {
        sqlx::query!("delete from queued_txs where tx_id = $1", tx_id.as_slice())
            .execute(&self.pool)
            .await
            .map_err(eyre::Error::from)?;

        Ok(())
    }

    #[instrument(skip(self, envelope))]
    async fn add_pending_envelope(&self, tx_id: TxId, envelope: &TxEnvelope) -> Result<()> {
        sqlx::query!(
            "update pending_txs set envelopes = envelopes || $1 where tx_id = $2",
            serde_json::to_value(envelope)?,
            tx_id.as_slice()
        )
        .execute(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn remove_pending_transaction(&self, tx_id: TxId) -> Result<()> {
        sqlx::query!("delete from pending_txs where tx_id = $1", tx_id.as_slice())
            .execute(&self.pool)
            .await
            .map_err(eyre::Error::from)?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn read_pending_transactions(
        &self,
        signer: Address,
        chain_id: u64,
    ) -> Result<Vec<PendingTransaction>> {
        let rows = sqlx::query!(
            "select * from pending_txs where sender = $1 and chain_id = $2",
            signer.as_slice(),
            chain_id as i32 // yikes!
        )
        .fetch_all(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        Ok(rows
            .into_iter()
            .map(|row| {
                Ok::<_, serde_json::Error>(PendingTransaction {
                    tx: serde_json::from_value(row.tx)?,
                    sent: serde_json::from_value(row.envelopes)?,
                    signer: Address::from_slice(&row.sender),
                    sent_at: DateTime::from_naive_utc_and_offset(row.sent_at, *Utc::now().offset()),
                })
            })
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    #[instrument(skip(self, status))]
    async fn write_transaction_status(
        &self,
        tx_id: TxId,
        status: &TransactionStatus,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(eyre::Error::from)?;
        sqlx::query!(
            r#"update txs set status = $1 where tx_id = $2"#,
            match status {
                TransactionStatus::InFlight => TxStatus::InFlight,
                TransactionStatus::Pending(_) => TxStatus::Pending,
                TransactionStatus::Confirmed(_) => TxStatus::Confirmed,
                TransactionStatus::Failed(_) => TxStatus::Failed,
            } as TxStatus,
            tx_id.as_slice(),
        )
        .execute(&mut *tx)
        .await
        .map_err(eyre::Error::from)?;

        if let TransactionStatus::Failed(error) = status {
            sqlx::query!(
                r#"update txs set error = $1 where tx_id = $2"#,
                error.to_string(),
                tx_id.as_slice()
            )
            .execute(&mut *tx)
            .await
            .map_err(eyre::Error::from)?;
        }

        match status {
            TransactionStatus::Pending(tx_hash) => {
                sqlx::query!(
                    r#"update txs set tx_hash = $1 where tx_id = $2"#,
                    tx_hash.as_slice(),
                    tx_id.as_slice(),
                )
                .execute(&mut *tx)
                .await
                .map_err(eyre::Error::from)?;
            }
            TransactionStatus::Confirmed(receipt) => {
                sqlx::query!(
                    r#"update txs set tx_hash = $1, receipt = $2 where tx_id = $3"#,
                    receipt.transaction_hash.as_slice(),
                    serde_json::to_value(receipt)?,
                    tx_id.as_slice(),
                )
                .execute(&mut *tx)
                .await
                .map_err(eyre::Error::from)?;
            }
            _ => {}
        }
        tx.commit().await.map_err(eyre::Error::from)?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn read_transaction_status(
        &self,
        tx: TxId,
    ) -> Result<Option<(ChainId, TransactionStatus)>> {
        let row = sqlx::query!(
            r#"select chain_id, tx_hash, status as "status: TxStatus", error, receipt from txs where tx_id = $1"#,
            tx.as_slice()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        row.map(|row| parse_transaction_status!(row)).transpose()
    }

    #[instrument(skip(self))]
    async fn read_transaction_statuses(
        &self,
        tx_ids: &[TxId],
    ) -> Result<Vec<Option<(ChainId, TransactionStatus)>>> {
        if tx_ids.is_empty() {
            return Ok(Vec::new());
        }

        let tx_id_bytes: Vec<Vec<u8>> = tx_ids.iter().map(|id| id.as_slice().to_vec()).collect();

        let rows = sqlx::query!(
            r#"select tx_id, chain_id, tx_hash, status as "status: TxStatus", error, receipt
               from txs
               where tx_id = ANY($1)
               order by array_position($1, tx_id)"#,
            &tx_id_bytes
        )
        .fetch_all(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        let mut map: HashMap<TxId, (ChainId, TransactionStatus)> = HashMap::default();
        for row in rows {
            map.insert(TxId::from_slice(&row.tx_id), parse_transaction_status!(row)?);
        }

        // Return results in the same order as input
        Ok(tx_ids.iter().map(|tx_id| map.get(tx_id).cloned()).collect())
    }

    #[instrument(skip(self))]
    async fn add_bundle_tx(&self, bundle: BundleId, tx: TxId) -> Result<()> {
        sqlx::query!(
            "insert into bundle_transactions (bundle_id, tx_id) values ($1, $2)",
            bundle.as_slice(),
            tx.as_slice()
        )
        .execute(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn get_bundle_transactions(&self, bundle: BundleId) -> Result<Vec<TxId>> {
        let rows = sqlx::query!(
            "select tx_id from bundle_transactions where bundle_id = $1",
            bundle.as_slice()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        Ok(rows.into_iter().map(|row| TxId::from_slice(&row.tx_id)).collect())
    }

    #[instrument(skip(self))]
    async fn queue_transaction(&self, tx: &RelayTransaction) -> Result<()> {
        let mut db_tx = self.pool.begin().await.map_err(eyre::Error::from)?;
        self.queue_transaction_with(tx, StoreTxData::Yes, &mut db_tx).await?;
        db_tx.commit().await.map_err(eyre::Error::from)?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn read_queued_transactions(&self, chain_id: u64) -> Result<Vec<RelayTransaction>> {
        let rows = sqlx::query!(
            "select * from queued_txs where chain_id = $1 order by id",
            chain_id as i32 // yikes!
        )
        .fetch_all(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        Ok(rows
            .into_iter()
            .map(|row| serde_json::from_value(row.tx))
            .collect::<std::result::Result<_, _>>()?)
    }

    #[instrument(skip_all)]
    async fn verified_email_exists(&self, email: &str) -> Result<bool> {
        let exists = sqlx::query!(
            "select * from emails where email = $1 and verified_at is not null",
            email
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(eyre::Error::from)?
        .is_some();

        Ok(exists)
    }

    #[instrument(skip_all)]
    async fn add_unverified_email(&self, account: Address, email: &str, token: &str) -> Result<()> {
        sqlx::query!(
            "insert into emails (address, email, token) values ($1, $2, $3) on conflict(address, email) do update set token = $3",
            account.as_slice(),
            email,
            token,
        )
        .execute(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        Ok(())
    }

    /// Verifies an unverified email in the database if the verification code is valid.
    ///
    /// Should remove any other verified emails for the same account address.
    ///
    /// Returns true if the email was verified successfully.
    #[instrument(skip_all)]
    async fn verify_email(&self, account: Address, email: &str, token: &str) -> Result<bool> {
        let affected = sqlx::query!(
            "update emails set verified_at = now() where address = $1 and email = $2 and token = $3",
            account.as_slice(),
            email,
            token
        )
        .execute(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        Ok(affected.rows_affected() > 0)
    }

    #[instrument(skip_all)]
    async fn verified_phone_exists(&self, phone: &str) -> Result<bool> {
        let exists = sqlx::query!(
            "select * from phones where phone = $1 and verified_at is not null",
            phone
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(eyre::Error::from)?
        .is_some();

        Ok(exists)
    }

    #[instrument(skip_all)]
    async fn add_unverified_phone(
        &self,
        account: Address,
        phone: &str,
        verification_sid: &str,
    ) -> Result<()> {
        sqlx::query!(
            "insert into phones (address, phone, verification_sid, attempts) values ($1, $2, $3, 0) 
             on conflict(address, phone) do update set verification_sid = $3, attempts = 0, created_at = now()",
            account.as_slice(),
            phone,
            verification_sid,
        )
        .execute(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        Ok(())
    }

    #[instrument(skip_all)]
    async fn mark_phone_verified(&self, account: Address, phone: &str) -> Result<()> {
        sqlx::query!(
            "update phones set verified_at = now() where address = $1 and phone = $2 and verified_at is null",
            account.as_slice(),
            phone
        )
        .execute(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        Ok(())
    }

    #[instrument(skip_all)]
    async fn get_phone_verification_attempts(&self, account: Address, phone: &str) -> Result<u32> {
        let record = sqlx::query!(
            "select attempts from phones where address = $1 and phone = $2",
            account.as_slice(),
            phone
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        Ok(record.map(|r| r.attempts as u32).unwrap_or(0))
    }

    #[instrument(skip_all)]
    async fn increment_phone_verification_attempts(
        &self,
        account: Address,
        phone: &str,
    ) -> Result<()> {
        sqlx::query!(
            "update phones set attempts = attempts + 1 where address = $1 and phone = $2",
            account.as_slice(),
            phone
        )
        .execute(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        Ok(())
    }

    #[instrument(skip_all)]
    async fn update_phone_verification_sid(
        &self,
        account: Address,
        phone: &str,
        verification_sid: &str,
    ) -> Result<()> {
        sqlx::query!(
            "update phones set verification_sid = $3 where address = $1 and phone = $2",
            account.as_slice(),
            phone,
            verification_sid
        )
        .execute(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        Ok(())
    }

    async fn get_onramp_verification_status(
        &self,
        account: Address,
    ) -> Result<OnrampVerificationStatus> {
        let email_row = sqlx::query!(
            "select extract(epoch from verified_at)::bigint as verified_at from emails where address = $1 and verified_at is not null",
            account.as_slice()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        let phone_row = sqlx::query!(
            "select extract(epoch from verified_at)::bigint as verified_at from phones where address = $1 and verified_at is not null",
            account.as_slice()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        Ok(OnrampVerificationStatus {
            email: email_row.and_then(|r| r.verified_at.map(|v| v as u64)),
            phone: phone_row.and_then(|r| r.verified_at.map(|v| v as u64)),
        })
    }

    async fn get_onramp_contact_info(&self, account: Address) -> Result<OnrampContactInfo> {
        // Get verified email if exists, otherwise get the last non-verified email
        let email_row = sqlx::query!(
            r#"
            select email from emails
            where address = $1
            order by verified_at is not null desc, created_at desc
            limit 1
            "#,
            account.as_slice()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        let phone_row = sqlx::query!(
            "select phone, extract(epoch from verified_at)::bigint as verified_at from phones where address = $1 and verified_at is not null",
            account.as_slice()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        Ok(OnrampContactInfo {
            email: email_row.map(|r| r.email),
            phone: phone_row.as_ref().map(|r| r.phone.clone()),
            phone_verified_at: phone_row.and_then(|r| r.verified_at.map(|v| v as u64)),
        })
    }

    #[instrument(skip_all)]
    async fn ping(&self) -> Result<()> {
        // acquire a connection to ensure DB is reachable
        self.pool.acquire().await.map_err(eyre::Error::from).map_err(Into::into).map(drop)
    }

    async fn store_pending_bundle(
        &self,
        bundle: &InteropBundle,
        status: BundleStatus,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO pending_bundles (bundle_id, status, bundle_data, created_at)
            VALUES ($1, $2, $3, NOW())
            "#,
            bundle.id.as_slice(),
            status as _,
            serde_json::to_value(bundle)?,
        )
        .execute(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        Ok(())
    }

    async fn update_pending_bundle_status(
        &self,
        bundle_id: BundleId,
        status: BundleStatus,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(eyre::Error::from)?;
        self.update_pending_bundle_status_with(bundle_id, status, &mut tx).await?;
        tx.commit().await.map_err(eyre::Error::from)?;
        Ok(())
    }

    async fn get_pending_bundles(&self) -> Result<Vec<BundleWithStatus>> {
        let rows = sqlx::query!(
            r#"
            SELECT status AS "status: BundleStatus", bundle_data
            FROM pending_bundles
            ORDER BY created_at
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        rows.into_iter()
            .map(|row| {
                let bundle: InteropBundle = serde_json::from_value(row.bundle_data)
                    .map_err(|e| eyre::eyre!("Failed to deserialize bundle: {}", e))?;
                Ok(BundleWithStatus { bundle, status: row.status })
            })
            .collect()
    }

    async fn get_pending_bundle(&self, bundle_id: BundleId) -> Result<Option<BundleWithStatus>> {
        let row = sqlx::query!(
            r#"
            SELECT status AS "status: BundleStatus", bundle_data
            FROM pending_bundles
            WHERE bundle_id = $1
            "#,
            bundle_id.as_slice()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        match row {
            Some(row) => {
                let bundle: InteropBundle = serde_json::from_value(row.bundle_data)
                    .map_err(|e| eyre::eyre!("Failed to deserialize bundle: {}", e))?;
                Ok(Some(BundleWithStatus { bundle, status: row.status }))
            }
            None => Ok(None),
        }
    }

    async fn update_bundle_and_queue_transactions(
        &self,
        bundle: &InteropBundle,
        status: BundleStatus,
        transactions: &[RelayTransaction],
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(eyre::Error::from)?;

        // First store the bundle with the new status
        self.store_pending_bundle_with(bundle, status, &mut tx).await?;

        // Then queue the specific transactions provided
        // Don't store tx data since it's already in bundle_data (avoid duplication)
        for relay_tx in transactions {
            self.queue_transaction_with(relay_tx, StoreTxData::No, &mut tx).await?;
        }

        tx.commit().await.map_err(eyre::Error::from)?;
        Ok(())
    }

    async fn move_bundle_to_finished(&self, bundle_id: BundleId) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(eyre::Error::from)?;

        // Move the bundle from pending to finished in a single transaction
        let result = sqlx::query!(
            r#"
            WITH moved AS (
                DELETE FROM pending_bundles
                WHERE bundle_id = $1
                RETURNING bundle_id, status, bundle_data, created_at
            )
            INSERT INTO finished_bundles (bundle_id, status, bundle_data, created_at, finished_at)
            SELECT bundle_id, status, bundle_data, created_at, NOW()
            FROM moved
            "#,
            bundle_id.as_slice()
        )
        .execute(&mut *tx)
        .await
        .map_err(eyre::Error::from)?;

        if result.rows_affected() == 0 {
            return Err(eyre::eyre!("Bundle not found: {:?}", bundle_id).into());
        }

        tx.commit().await.map_err(eyre::Error::from)?;
        Ok(())
    }

    async fn get_interop_status(&self, bundle_id: BundleId) -> Result<Option<BundleStatus>> {
        let row = sqlx::query!(
            r#"
            SELECT status as "status: BundleStatus"
            FROM (
                SELECT status FROM pending_bundles WHERE bundle_id = $1
                UNION ALL
                SELECT status FROM finished_bundles WHERE bundle_id = $1
            ) AS combined
            LIMIT 1
            "#,
            bundle_id.as_slice()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        Ok(row.and_then(|r| r.status))
    }

    async fn get_finished_interop_bundle(
        &self,
        bundle_id: BundleId,
    ) -> Result<Option<BundleWithStatus>> {
        let row = sqlx::query!(
            r#"
            SELECT bundle_id, status as "status: BundleStatus", bundle_data, created_at
            FROM finished_bundles
            WHERE bundle_id = $1
            "#,
            bundle_id.as_slice()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        let Some(row) = row else {
            return Ok(None);
        };

        let bundle: InteropBundle = serde_json::from_value(row.bundle_data)
            .map_err(|e| eyre::eyre!("Failed to deserialize bundle: {}", e))?;

        Ok(Some(BundleWithStatus { bundle, status: row.status }))
    }

    async fn store_pending_refund(
        &self,
        bundle_id: BundleId,
        refund_timestamp: DateTime<Utc>,
        new_status: BundleStatus,
    ) -> Result<()> {
        // Perform both operations atomically in a transaction
        let mut tx = self.pool.begin().await.map_err(eyre::Error::from)?;

        // Store the pending refund
        sqlx::query!(
            r#"
            INSERT INTO pending_refunds (bundle_id, refund_timestamp)
            VALUES ($1, $2)
            ON CONFLICT (bundle_id) DO UPDATE SET
                refund_timestamp = GREATEST(pending_refunds.refund_timestamp, EXCLUDED.refund_timestamp)
            "#,
            bundle_id.0.as_slice(),
            refund_timestamp
        )
        .execute(&mut *tx)
        .await
        .map_err(eyre::Error::from)?;

        // Update the bundle status
        self.update_pending_bundle_status_with(bundle_id, new_status, &mut tx).await?;

        tx.commit().await.map_err(eyre::Error::from)?;
        Ok(())
    }

    #[instrument(skip_all)]
    async fn lock_liquidity_for_bundle(
        &self,
        assets: HashMap<ChainAddress, LockLiquidityInput>,
        bundle_id: BundleId,
        status: BundleStatus,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(eyre::Error::from)?;

        self.try_lock_liquidity_with(assets, &mut tx).await?;
        self.update_pending_bundle_status_with(bundle_id, status, &mut tx).await?;

        tx.commit().await.map_err(eyre::Error::from)?;

        Ok(())
    }

    #[instrument(skip_all)]
    async fn unlock_bundle_liquidity(
        &self,
        bundle: &InteropBundle,
        receipts: HashMap<TxId, TransactionReceipt>,
        status: BundleStatus,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(eyre::Error::from)?;

        for transfer in &bundle.asset_transfers {
            let block =
                receipts.get(&transfer.tx_id).and_then(|r| r.block_number).unwrap_or_default();
            self.unlock_liquidity_with(
                (transfer.chain_id, transfer.asset_address),
                transfer.amount,
                block,
                &mut *tx,
            )
            .await?;
        }

        self.update_pending_bundle_status_with(bundle.id, status, &mut tx).await?;

        tx.commit().await.map_err(eyre::Error::from)?;

        Ok(())
    }

    #[instrument(skip_all)]
    async fn get_total_locked_at(&self, asset: ChainAddress, at: BlockNumber) -> Result<U256> {
        let locked = sqlx::query!(
            "select coalesce(sum(amount), 0) from locked_liquidity where chain_id = $1 and asset_address = $2",
            asset.0 as i64,
            asset.1.as_slice(),
        )
        .fetch_one(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        let unlocked = sqlx::query!(
            "select coalesce(sum(amount), 0) from pending_unlocks where chain_id = $1 and asset_address = $2 and block_number <= $3",
            asset.0 as i64,
            asset.1.as_slice(),
            at as i64,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        let locked = numeric_to_u256(&locked.coalesce.unwrap_or_default());
        let unlocked = numeric_to_u256(&unlocked.coalesce.unwrap_or_default());

        Ok(locked.saturating_sub(unlocked))
    }

    #[instrument(skip_all)]
    async fn prune_unlocked_entries(&self, chain_id: ChainId, until: BlockNumber) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(eyre::Error::from)?;

        let rows = sqlx::query!(
            "delete from pending_unlocks where chain_id = $1 and block_number <= $2 returning *",
            chain_id as i64,
            until as i64,
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(eyre::Error::from)?;

        for row in rows {
            sqlx::query!(
                "update locked_liquidity set amount = amount - $1 where chain_id = $2 and asset_address = $3",
                row.amount,
                chain_id as i64,
                row.asset_address.as_slice(),
            )
            .execute(&mut *tx)
            .await
            .map_err(eyre::Error::from)?;
        }

        tx.commit().await.map_err(eyre::Error::from)?;

        Ok(())
    }

    #[instrument(skip_all)]
    async fn lock_liquidity_for_bridge(
        &self,
        transfer: &BridgeTransfer,
        input: LockLiquidityInput,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(eyre::Error::from)?;

        self.try_lock_liquidity_with(HashMap::from_iter([(transfer.from, input)]), &mut tx).await?;
        sqlx::query!(
            "insert into bridge_transfers (transfer_id, transfer_data) values ($1, $2)",
            transfer.id.as_slice(),
            serde_json::to_value(transfer)?,
        )
        .execute(&mut *tx)
        .await
        .map_err(eyre::Error::from)?;

        tx.commit().await.map_err(eyre::Error::from)?;
        Ok(())
    }

    async fn get_total_locked_liquidity(&self) -> Result<HashMap<ChainAddress, U256>> {
        let rows = sqlx::query!(
            r#"
            SELECT chain_id, asset_address, amount
            FROM locked_liquidity
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        let mut result = HashMap::default();
        for row in rows {
            result.insert(
                (row.chain_id as u64, Address::from_slice(&row.asset_address)),
                numeric_to_u256(&row.amount),
            );
        }
        Ok(result)
    }

    async fn get_total_pending_unlocks(&self) -> Result<HashMap<ChainAddress, U256>> {
        let rows = sqlx::query!(
            r#"
            SELECT chain_id, asset_address, SUM(amount) AS "amount!: BigDecimal"
            FROM pending_unlocks
            GROUP BY chain_id, asset_address
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        let mut result = HashMap::default();
        for row in rows {
            result.insert(
                (row.chain_id as u64, Address::from_slice(&row.asset_address)),
                numeric_to_u256(&row.amount),
            );
        }
        Ok(result)
    }

    async fn get_pending_refunds_ready(
        &self,
        current_time: DateTime<Utc>,
    ) -> Result<Vec<(BundleId, DateTime<Utc>)>> {
        let rows = sqlx::query!(
            r#"
            SELECT bundle_id, refund_timestamp
            FROM pending_refunds
            WHERE refund_timestamp <= $1
            ORDER BY refund_timestamp ASC
            "#,
            current_time
        )
        .fetch_all(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        Ok(rows
            .into_iter()
            .map(|row| {
                let bundle_id = BundleId(B256::from_slice(&row.bundle_id));
                (bundle_id, row.refund_timestamp)
            })
            .collect())
    }

    /// Updates a bridge-specific data for a transfer.
    async fn update_transfer_bridge_data(
        &self,
        transfer_id: BridgeTransferId,
        data: &serde_json::Value,
    ) -> Result<()> {
        sqlx::query!(
            "update bridge_transfers set bridge_data = $1 where transfer_id = $2",
            data,
            transfer_id.as_slice(),
        )
        .execute(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        Ok(())
    }

    async fn get_transfer_bridge_data(
        &self,
        transfer_id: BridgeTransferId,
    ) -> Result<Option<serde_json::Value>> {
        let row = sqlx::query!(
            "select bridge_data from bridge_transfers where transfer_id = $1",
            transfer_id.as_slice(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        Ok(row.and_then(|r| r.bridge_data))
    }

    async fn update_transfer_state(
        &self,
        transfer_id: BridgeTransferId,
        state: BridgeTransferState,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(eyre::Error::from)?;

        self.update_transfer_state_with(transfer_id, state, &mut tx).await?;

        tx.commit().await.map_err(eyre::Error::from)?;

        Ok(())
    }

    async fn update_transfer_state_and_unlock_liquidity(
        &self,
        transfer_id: BridgeTransferId,
        state: BridgeTransferState,
        at: BlockNumber,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(eyre::Error::from)?;

        let Some(transfer) = self.load_transfer_with(transfer_id, &mut *tx).await? else {
            return Err(eyre!("transfer not found").into());
        };

        self.update_transfer_state_with(transfer_id, state, &mut tx).await?;
        self.unlock_liquidity_with(transfer.from, transfer.amount, at, &mut *tx).await?;

        tx.commit().await.map_err(eyre::Error::from)?;

        Ok(())
    }

    async fn get_transfer_state(
        &self,
        transfer_id: BridgeTransferId,
    ) -> Result<Option<BridgeTransferState>> {
        let row = sqlx::query_as!(
            BridgeTransferRow,
            "select status as \"status: BridgeTransferStatus\", outbound_block_number, inbound_block_number from bridge_transfers where transfer_id = $1",
            transfer_id.as_slice(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        let Some(row) = row else {
            return Ok(None);
        };

        let state = match row.status {
            BridgeTransferStatus::Pending => BridgeTransferState::Pending,
            BridgeTransferStatus::Sent => {
                let block_number = row.outbound_block_number.unwrap_or(0) as u64;
                BridgeTransferState::Sent(block_number)
            }
            BridgeTransferStatus::OutboundFailed => BridgeTransferState::OutboundFailed,
            BridgeTransferStatus::Completed => {
                let block_number = row.inbound_block_number.unwrap_or(0) as u64;
                BridgeTransferState::Completed(block_number)
            }
            BridgeTransferStatus::InboundFailed => BridgeTransferState::InboundFailed,
        };

        Ok(Some(state))
    }

    async fn load_pending_transfers(&self) -> Result<Vec<BridgeTransfer>> {
        let rows = sqlx::query!(
            r#"
            select transfer_data
            from bridge_transfers
            where status IN ('pending', 'sent')
            ORDER BY transfer_id
            "#
        )
        .fetch_all(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        let mut transfers = Vec::new();
        for row in rows {
            transfers.push(serde_json::from_value(row.transfer_data)?);
        }

        Ok(transfers)
    }

    async fn remove_processed_refund(&self, bundle_id: BundleId) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(eyre::Error::from)?;
        self.remove_processed_refund_with(bundle_id, &mut tx).await?;
        tx.commit().await.map_err(eyre::Error::from)?;
        Ok(())
    }

    async fn mark_refund_ready(&self, bundle_id: BundleId, new_status: BundleStatus) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(eyre::Error::from)?;

        self.update_pending_bundle_status_with(bundle_id, new_status, &mut tx).await?;
        self.remove_processed_refund_with(bundle_id, &mut tx).await?;

        tx.commit().await.map_err(eyre::Error::from)?;
        Ok(())
    }

    #[instrument(skip_all)]
    async fn lock_liquidity_for_pull_gas(
        &self,
        transaction: &TxEnvelope,
        signer: Address,
        input: LockLiquidityInput,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(eyre::Error::from)?;

        let chain_id = transaction.chain_id().unwrap_or(0);
        self.try_lock_liquidity_with(
            HashMap::from_iter([((chain_id, Address::ZERO), input)]),
            &mut tx,
        )
        .await?;

        let transaction_json = serde_json::to_value(transaction)?;
        sqlx::query!(
            r#"
            INSERT INTO pull_gas_transactions
            (id, signer_address, chain_id, state, transaction_data)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            transaction.tx_hash().as_slice(),
            signer.as_slice(),
            chain_id as i64,
            PullGasState::Pending as PullGasState,
            transaction_json,
        )
        .execute(&mut *tx)
        .await
        .map_err(eyre::Error::from)?;

        tx.commit().await.map_err(eyre::Error::from)?;
        Ok(())
    }

    #[instrument(skip_all)]
    async fn update_pull_gas_and_unlock_liquidity(
        &self,
        tx_hash: B256,
        chain_id: ChainId,
        amount: U256,
        state: PullGasState,
        at: BlockNumber,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(eyre::Error::from)?;

        sqlx::query!(
            r#"
            UPDATE pull_gas_transactions
            SET state = $2,
                updated_at = NOW()
            WHERE id = $1
            "#,
            tx_hash.as_slice(),
            state as PullGasState,
        )
        .execute(&mut *tx)
        .await
        .map_err(eyre::Error::from)?;

        self.unlock_liquidity_with((chain_id, Address::ZERO), amount, at, &mut *tx).await?;

        tx.commit().await.map_err(eyre::Error::from)?;
        Ok(())
    }

    #[instrument(skip_all)]
    async fn load_pending_pull_gas_transactions(
        &self,
        signer: Address,
        chain_id: ChainId,
    ) -> Result<Vec<TxEnvelope>> {
        let rows = sqlx::query!(
            r#"
            SELECT transaction_data
            FROM pull_gas_transactions
            WHERE signer_address = $1
            AND chain_id = $2
            AND state = 'pending'
            ORDER BY created_at
            "#,
            signer.as_slice(),
            chain_id as i64,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        let mut pending_transactions = Vec::new();
        for row in rows {
            let transaction: TxEnvelope = serde_json::from_value(row.transaction_data)?;
            pending_transactions.push(transaction);
        }

        Ok(pending_transactions)
    }

    #[instrument(skip_all)]
    async fn store_precall(&self, chain_id: ChainId, call: SignedCall) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO precalls (chain_id, address, data, nonce)
            VALUES ($1, $2, $3, $4)
            "#,
            chain_id as i64,
            call.eoa.as_slice(),
            serde_json::to_value(&call)?,
            call.nonce.as_le_slice(),
        )
        .execute(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        Ok(())
    }

    #[instrument(skip_all)]
    async fn read_precalls_for_eoa(
        &self,
        chain_id: ChainId,
        eoa: Address,
    ) -> Result<Vec<SignedCall>> {
        let rows = sqlx::query!(
            r#"
            SELECT data
            FROM precalls
            WHERE chain_id = $1 AND address = $2
            "#,
            chain_id as i64,
            eoa.as_slice(),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        Ok(rows.into_iter().map(|row| serde_json::from_value(row.data).unwrap()).collect())
    }

    #[instrument(skip_all)]
    async fn remove_precall(&self, chain_id: ChainId, eoa: Address, nonce: U256) -> Result<()> {
        sqlx::query!(
            r#"
            DELETE FROM precalls WHERE chain_id = $1 AND address = $2 AND nonce = $3
            "#,
            chain_id as i64,
            eoa.as_slice(),
            nonce.as_le_slice(),
        )
        .execute(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        Ok(())
    }

    async fn get_bundles_by_address(
        &self,
        address: Address,
        limit: u64,
        offset: u64,
        sort_desc: bool,
    ) -> Result<Vec<BundleHistoryEntry>> {
        let eoa_hex = format!("0x{}", hex::encode(address.as_slice()));
        let order = if sort_desc { "DESC" } else { "ASC" };
        let per_branch_limit = limit + offset;

        // Note: Using format!() here because ORDER BY direction and LIMIT are runtime parameters.
        let query = format!(
            r#"
            WITH all_bundles AS (
                (
                    SELECT
                        bundle_id,
                        status,
                        bundle_data,
                        COALESCE(finished_at, created_at) as timestamp,
                        'multichain' as bundle_type,
                        NULL::bigint as chain_id,
                        NULL::bytea as tx_hash
                    FROM (
                        (
                            SELECT bundle_id, status, bundle_data, created_at, NULL::timestamptz as finished_at
                            FROM pending_bundles
                            WHERE bundle_data->'dst_txs'->0->'quote'->'intent'->>'eoa' = $1
                            ORDER BY created_at {}
                            LIMIT {}
                        )
                        UNION ALL
                        (
                            SELECT bundle_id, status, bundle_data, created_at, finished_at
                            FROM finished_bundles
                            WHERE bundle_data->'dst_txs'->0->'quote'->'intent'->>'eoa' = $1
                            ORDER BY finished_at {}
                            LIMIT {}
                        )
                    ) mc
                    ORDER BY COALESCE(finished_at, created_at) {}
                    LIMIT {}
                )
                UNION ALL
                (
                    SELECT
                        bt.bundle_id,
                        NULL as status,
                        t.tx as bundle_data,
                        tx_received_at_immutable(t.tx) as timestamp,
                        'singlechain' as bundle_type,
                        t.chain_id,
                        t.tx_hash
                    FROM bundle_transactions bt
                    JOIN txs t ON bt.tx_id = t.tx_id
                    WHERE t.tx IS NOT NULL
                    AND t.tx->'quote'->'intent'->>'eoa' = $1
                    AND NOT EXISTS (SELECT 1 FROM pending_bundles WHERE bundle_id = bt.bundle_id)
                    AND NOT EXISTS (SELECT 1 FROM finished_bundles WHERE bundle_id = bt.bundle_id)
                    ORDER BY tx_received_at_immutable(t.tx) {}
                    LIMIT {}
                )
            )
            SELECT * FROM all_bundles
            ORDER BY timestamp {}
            LIMIT $2 OFFSET $3
            "#,
            order,
            per_branch_limit,
            order,
            per_branch_limit,
            order,
            per_branch_limit,
            order,
            per_branch_limit,
            order
        );

        let rows = sqlx::query(&query)
            .bind(&eoa_hex)
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&self.pool)
            .await
            .map_err(eyre::Error::from)?;

        let mut entries = Vec::new();
        for row in rows {
            let bundle_type: String = row.get("bundle_type");
            let timestamp: chrono::DateTime<chrono::Utc> = row.get("timestamp");
            let timestamp = timestamp.timestamp() as u64;

            match bundle_type.as_str() {
                "multichain" => {
                    let bundle_data: serde_json::Value = row.get("bundle_data");
                    let bundle: InteropBundle = serde_json::from_value(bundle_data)
                        .map_err(|e| eyre::eyre!("Failed to deserialize InteropBundle: {}", e))?;
                    let status: BundleStatus = row
                        .try_get("status")
                        .map_err(|e| eyre::eyre!("Failed to get BundleStatus: {}", e))?;

                    entries.push(BundleHistoryEntry::Interop {
                        bundle: Box::new(BundleWithStatus { bundle, status }),
                        timestamp,
                    });
                }
                "singlechain" => {
                    let bundle_id_bytes: Vec<u8> = row.get("bundle_id");
                    let bundle_id = BundleId::from_slice(&bundle_id_bytes);
                    let chain_id: i64 = row.get("chain_id");
                    let tx_hash: Option<TxHash> =
                        row.try_get::<Vec<u8>, _>("tx_hash").ok().map(|v| TxHash::from_slice(&v));

                    // bundle_data might be NULL for old transactions (backwards compatibility)
                    let tx_data: Option<serde_json::Value> = row.try_get("bundle_data").ok();

                    let quote = if let Some(tx_data) = tx_data {
                        let relay_tx: RelayTransaction =
                            serde_json::from_value(tx_data).map_err(|e| {
                                eyre::eyre!("Failed to deserialize RelayTransaction: {}", e)
                            })?;

                        match relay_tx.kind {
                            RelayTransactionKind::Intent { quote, .. } => Some((*quote).clone()),
                            _ => continue, // Skip non-intent transactions
                        }
                    } else {
                        // Old transaction without stored data - still show in history but without
                        // quote
                        None
                    };

                    entries.push(BundleHistoryEntry::SingleChain {
                        bundle_id,
                        chain_id: chain_id as u64,
                        quote: quote.map(Box::new),
                        tx_hash,
                        timestamp,
                    });
                }
                _ => continue,
            }
        }

        Ok(entries)
    }

    async fn get_bundle_count_by_address(&self, address: Address) -> Result<u64> {
        let eoa_hex = format!("0x{}", hex::encode(address.as_slice()));

        let query = r#"
            SELECT
                (
                    SELECT COUNT(*)
                    FROM pending_bundles
                    WHERE bundle_data->'dst_txs'->0->'quote'->'intent'->>'eoa' = $1
                ) +
                (
                    SELECT COUNT(*)
                    FROM finished_bundles
                    WHERE bundle_data->'dst_txs'->0->'quote'->'intent'->>'eoa' = $1
                ) +
                (
                    SELECT COUNT(*)
                    FROM bundle_transactions bt
                    JOIN txs t ON bt.tx_id = t.tx_id
                    WHERE t.tx IS NOT NULL
                    AND t.tx->'quote'->'intent'->>'eoa' = $1
                    AND NOT EXISTS (SELECT 1 FROM pending_bundles WHERE bundle_id = bt.bundle_id)
                    AND NOT EXISTS (SELECT 1 FROM finished_bundles WHERE bundle_id = bt.bundle_id)
                ) as total
        "#;

        let row = sqlx::query(query)
            .bind(&eoa_hex)
            .fetch_one(&self.pool)
            .await
            .map_err(eyre::Error::from)?;

        let total: i64 = row.get("total");
        Ok(total as u64)
    }

    #[instrument(skip_all)]
    async fn store_historical_usd_prices(&self, prices: Vec<HistoricalPrice>) -> Result<()> {
        if prices.is_empty() {
            return Ok(());
        }

        let asset_uids: Vec<String> =
            prices.iter().map(|p| p.asset_uid.as_str().to_string()).collect();
        let timestamps: Vec<i64> = prices.iter().map(|p| p.timestamp as i64).collect();
        let usd_prices: Vec<f64> = prices.iter().map(|p| p.usd_price).collect();

        sqlx::query!(
            r#"
            INSERT INTO historical_usd_prices (asset_uid, timestamp, usd_price)
            SELECT * FROM UNNEST($1::text[], $2::bigint[], $3::double precision[])
            ON CONFLICT (asset_uid, timestamp) DO UPDATE SET usd_price = EXCLUDED.usd_price
            "#,
            &asset_uids[..],
            &timestamps[..],
            &usd_prices[..]
        )
        .execute(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        Ok(())
    }

    #[instrument(skip_all)]
    async fn read_historical_usd_prices(
        &self,
        queries: Vec<HistoricalPriceKey>,
    ) -> Result<HashMap<HistoricalPriceKey, (u64, f64)>> {
        if queries.is_empty() {
            return Ok(HashMap::default());
        }

        let asset_uids: Vec<String> =
            queries.iter().map(|q| q.asset_uid.as_str().to_string()).collect();
        let timestamps: Vec<i64> = queries.iter().map(|q| q.timestamp as i64).collect();

        // Try exact matches first
        let rows = sqlx::query!(
            r#"
            SELECT asset_uid, timestamp, usd_price
            FROM historical_usd_prices
            WHERE (asset_uid, timestamp) IN (
                SELECT * FROM UNNEST($1::text[], $2::bigint[])
            )
            "#,
            &asset_uids[..],
            &timestamps[..]
        )
        .fetch_all(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        let mut result = HashMap::default();
        for row in rows {
            let key = HistoricalPriceKey {
                asset_uid: AssetUid::new(row.asset_uid.clone()),
                timestamp: row.timestamp as u64,
            };
            result.insert(key, (row.timestamp as u64, row.usd_price));
        }

        // For queries that didn't get exact matches, try approximate lookup (±5 minutes)
        let missing_queries: Vec<_> =
            queries.into_iter().filter(|q| !result.contains_key(q)).collect();

        if !missing_queries.is_empty() {
            let missing_asset_uids: Vec<String> =
                missing_queries.iter().map(|q| q.asset_uid.as_str().to_string()).collect();
            let missing_timestamps: Vec<i64> =
                missing_queries.iter().map(|q| q.timestamp as i64).collect();

            // Use LATERAL JOIN to find closest timestamp within ±5 minutes for each query
            let approx_rows = sqlx::query!(
                r#"
                SELECT
                    q.asset_uid,
                    q.requested_timestamp,
                    h.timestamp,
                    h.usd_price
                FROM UNNEST($1::text[], $2::bigint[]) AS q(asset_uid, requested_timestamp)
                LEFT JOIN LATERAL (
                    SELECT timestamp, usd_price
                    FROM historical_usd_prices
                    WHERE asset_uid = q.asset_uid
                      AND timestamp BETWEEN q.requested_timestamp - 300
                                        AND q.requested_timestamp + 300
                    ORDER BY ABS(timestamp - q.requested_timestamp)
                    LIMIT 1
                ) h ON true
                WHERE h.timestamp IS NOT NULL
                "#,
                &missing_asset_uids[..],
                &missing_timestamps[..]
            )
            .fetch_all(&self.pool)
            .await
            .map_err(eyre::Error::from)?;

            for row in approx_rows {
                // SAFETY: WHERE h.timestamp IS NOT NULL ensures rows from LATERAL join exist
                // q.asset_uid and q.requested_timestamp are from UNNEST so they're nullable
                // h.timestamp and h.usd_price are from the lateral join and filtered by WHERE
                // clause
                let Some(asset_uid) = row.asset_uid else { continue };
                let Some(requested_timestamp) = row.requested_timestamp else { continue };

                let key = HistoricalPriceKey {
                    asset_uid: AssetUid::new(asset_uid),
                    timestamp: requested_timestamp as u64,
                };
                result.insert(key, (row.timestamp as u64, row.usd_price));
            }
        }

        Ok(result)
    }
}
