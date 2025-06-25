//! Relay storage implementation using a PostgreSQL database.

use std::{collections::HashMap, sync::Arc};

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
    primitives::{Address, B256, BlockNumber, ChainId, U256},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use eyre::eyre;
use num_traits::cast::ToPrimitive;
use sqlx::{Connection, PgPool, types::BigDecimal};
use tracing::instrument;

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

        row.map(|row| {
            let tx_hash = row.tx_hash.as_ref().map(|hash| B256::from_slice(hash));

            Ok((
                row.chain_id as u64,
                match row.status {
                    TxStatus::InFlight => TransactionStatus::InFlight,
                    // SAFETY: it should never be possible to have a pending transaction without a
                    // hash in the database
                    TxStatus::Pending => TransactionStatus::Pending(tx_hash.unwrap()),
                    // SAFETY: it should never be possible to have a confirmed transaction without a
                    // receipt in the database
                    TxStatus::Confirmed => TransactionStatus::Confirmed(
                        serde_json::from_value(row.receipt.unwrap()).map_err(eyre::Error::from)?,
                    ),
                    TxStatus::Failed => TransactionStatus::Failed(Arc::new(
                        row.error.unwrap_or_else(|| "transaction failed".to_string()),
                    )),
                },
            ))
        })
        .transpose()
    }

    #[instrument(skip(self))]
    async fn add_bundle_tx(&self, bundle: BundleId, chain_id: ChainId, tx: TxId) -> Result<()> {
        sqlx::query!(
            "insert into txs (tx_id, bundle_id, chain_id) values ($1, $2, $3)",
            tx.as_slice(),
            bundle.as_slice(),
            chain_id as i64 // yikes..
        )
        .execute(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn get_bundle_transactions(&self, bundle: BundleId) -> Result<Vec<TxId>> {
        let rows = sqlx::query!("select tx_id from txs where bundle_id = $1", bundle.as_slice())
            .fetch_all(&self.pool)
            .await
            .map_err(eyre::Error::from)?;

        Ok(rows.into_iter().map(|row| TxId::from_slice(&row.tx_id)).collect())
    }

    #[instrument(skip(self))]
    async fn write_queued_transaction(&self, tx: &RelayTransaction) -> Result<()> {
        sqlx::query!(
            "insert into queued_txs (chain_id, tx_id, tx) values ($1, $2, $3)",
            tx.chain_id() as i64, // yikes!
            tx.id.as_slice(),
            serde_json::to_value(&tx)?,
        )
        .execute(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

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

    async fn ping(&self) -> Result<()> {
        if let Some(mut connection) = self.pool.try_acquire() {
            connection.ping().await.map_err(eyre::Error::from).map_err(Into::into)
        } else {
            Err(eyre!("no connection to database").into())
        }
    }

    async fn try_lock_liquidity(
        &self,
        assets: HashMap<ChainAddress, LockLiquidityInput>,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(eyre::Error::from)?;

        let (chain_ids, asset_addresses): (Vec<_>, Vec<_>) = assets
            .iter()
            .map(|((chain, asset), _)| (*chain as i64, asset.as_slice().to_vec()))
            .unzip();

        let locked = sqlx::query!(
            "select * from locked_liquidity where (chain_id, asset_address) = ANY(SELECT unnest($1::bigint[]), unnest($2::bytea[]))",
            &chain_ids,
            &asset_addresses
        )
        .fetch_all(&mut *tx)
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
            .execute(&mut *tx)
            .await
            .map_err(eyre::Error::from)?;
        }

        // select all locked assets for update
        let locked = sqlx::query!(
            "select * from locked_liquidity where (chain_id, asset_address) = ANY(SELECT unnest($1::bigint[]), unnest($2::bytea[])) for update",
            &chain_ids,
            &asset_addresses
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(eyre::Error::from)?;

        // select all unlocked assets
        let unlocked = sqlx::query!(
            "select * from pending_unlocks where (chain_id, asset_address) = ANY(SELECT unnest($1::bigint[]), unnest($2::bytea[])) for update",
            &chain_ids,
            &asset_addresses
        )
        .fetch_all(&mut *tx)
        .await.map_err(eyre::Error::from)?;

        for ((chain, asset), input) in assets {
            let locked = locked
                .iter()
                .find(|row| row.chain_id == chain as i64 && row.asset_address == asset.as_slice())
                .map(|row| {
                    row.amount
                        .to_f64()
                        .map(U256::from)
                        .ok_or(StorageError::InternalError(eyre::eyre!("overflow")))
                })
                .transpose()?
                .unwrap_or_default();

            let unlocked = unlocked
                .iter()
                .filter(|row| {
                    row.chain_id == chain as i64
                        && row.asset_address == asset.as_slice()
                        && row.block_number <= input.balance_at as i64
                })
                .map(|row| {
                    row.amount
                        .to_f64()
                        .map(U256::from)
                        .ok_or(StorageError::InternalError(eyre::eyre!("overflow")))
                })
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .sum::<U256>();

            if input.current_balance + unlocked >= locked + input.lock_amount {
                sqlx::query!(
                    "update locked_liquidity set amount = $1 where chain_id = $2 and asset_address = $3",
                    BigDecimal::try_from(f64::from(locked + input.lock_amount)).map_err(eyre::Error::from)?,
                    chain as i64,
                    asset.as_slice()
                )
                .execute(&mut *tx)
                .await
                .map_err(eyre::Error::from)?;
            } else {
                return Err(StorageError::CantLockLiquidity);
            }
        }

        tx.commit().await.map_err(eyre::Error::from)?;

        Ok(())
    }

    async fn unlock_liquidity(
        &self,
        asset: ChainAddress,
        amount: U256,
        at: BlockNumber,
    ) -> Result<()> {
        sqlx::query!(
            "insert into pending_unlocks (chain_id, asset_address, amount, block_number) values ($1, $2, $3, $4)",
            asset.0 as i64,
            asset.1.as_slice(),
            BigDecimal::try_from(f64::from(amount)).map_err(eyre::Error::from)?,
            at as i64,
        )
        .execute(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        Ok(())
    }

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

        let locked =
            locked.coalesce.unwrap_or_default().to_f64().map(U256::from).unwrap_or_default();
        let unlocked =
            unlocked.coalesce.unwrap_or_default().to_f64().map(U256::from).unwrap_or_default();

        Ok(locked.saturating_sub(unlocked))
    }

    async fn remove_unlocked_entries(&self, chain_id: ChainId, until: BlockNumber) -> Result<()> {
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
}
