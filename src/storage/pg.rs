//! Relay storage implementation using a PostgreSQL database.

use std::sync::Arc;

use super::{StorageApi, api::Result};
use crate::{
    transactions::{PendingTransaction, RelayTransaction, TransactionStatus, TxId},
    types::{CreatableAccount, KeyID, rpc::BundleId},
};
use alloy::{
    consensus::TxEnvelope,
    primitives::{Address, B256, ChainId},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
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
    async fn read_prep(&self, address: &Address) -> Result<Option<CreatableAccount>> {
        let row =
            sqlx::query!(r#"select account from accounts where address = $1"#, address.as_slice())
                .fetch_optional(&self.pool)
                .await
                .map_err(eyre::Error::from)?;

        Ok(row.and_then(|row| serde_json::from_value(row.account).ok()))
    }

    #[instrument(skip_all)]
    async fn write_prep(&self, account: CreatableAccount) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(eyre::Error::from)?;
        sqlx::query!(
            "insert into accounts (address, account) values ($1, $2)",
            account.prep.address.as_slice(),
            serde_json::to_value(&account)?
        )
        .execute(&mut *tx)
        .await
        .map_err(eyre::Error::from)?;

        for id_sig in &account.id_signatures {
            sqlx::query!(
                "insert into keys (key_id, account_address, key_hash, signature) values ($1, $2, $3, $4)",
                id_sig.id.as_slice(),
                account.prep.address.as_slice(),
                id_sig.hash.as_slice(),
                &id_sig.signature.as_bytes()
            )
            .execute(&mut *tx)
            .await
            .map_err(eyre::Error::from)?;
        }
        tx.commit().await.map_err(eyre::Error::from)?;

        Ok(())
    }

    #[instrument(self)]
    async fn read_accounts_from_id(&self, id: &KeyID) -> Result<Vec<Address>> {
        let rows =
            sqlx::query!("select account_address from keys where key_id = $1", id.as_slice())
                .fetch_all(&self.pool)
                .await
                .map_err(eyre::Error::from)?;

        Ok(rows.into_iter().map(|row| Address::from_slice(&row.account_address)).collect())
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
            TransactionStatus::Pending(tx_hash) | TransactionStatus::Confirmed(tx_hash) => {
                sqlx::query!(
                    r#"update txs set tx_hash = $1 where tx_id = $2"#,
                    tx_hash.as_slice(),
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
            r#"select chain_id, tx_hash, status as "status: TxStatus", error from txs where tx_id = $1"#,
            tx.as_slice()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(eyre::Error::from)?;

        Ok(row.map(|row| {
            let tx_hash = row.tx_hash.map(|hash| B256::from_slice(&hash));

            (
                row.chain_id as u64,
                match row.status {
                    TxStatus::InFlight => TransactionStatus::InFlight,
                    // SAFETY: it should never be possible to have a pending transaction without a
                    // hash in the database
                    TxStatus::Pending => TransactionStatus::Pending(tx_hash.unwrap()),
                    // SAFETY: it should never be possible to have a confirmed transaction without a
                    // hash in the database
                    TxStatus::Confirmed => TransactionStatus::Confirmed(tx_hash.unwrap()),
                    TxStatus::Failed => TransactionStatus::Failed(Arc::new(
                        row.error.unwrap_or_else(|| "transaction failed".to_string()),
                    )),
                },
            )
        }))
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
}
