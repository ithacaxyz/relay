//! Relay storage implementation using a PostgreSQL database.

use std::sync::Arc;

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
    primitives::{Address, B256, ChainId},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use eyre::eyre;
use sqlx::{Connection, PgPool};
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

    /// Queue a single transaction within an existing database transaction
    async fn queue_transaction_with(
        &self,
        relay_tx: &RelayTransaction,
        tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    ) -> Result<()> {
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
        let mut db_tx = self.pool.begin().await.map_err(eyre::Error::from)?;
        self.queue_transaction_with(tx, &mut db_tx).await?;
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

    async fn queue_bundle_transactions(
        &self,
        bundle: &InteropBundle,
        status: BundleStatus,
        tx_type: InteropTxType,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(eyre::Error::from)?;

        // Queue the appropriate transactions
        let transactions = if tx_type.is_source() { &bundle.src_txs } else { &bundle.dst_txs };

        for relay_tx in transactions {
            self.queue_transaction_with(relay_tx, &mut tx).await?;
        }

        // Update bundle status
        self.update_pending_bundle_status_with(bundle.id, status, &mut tx).await?;

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
}
