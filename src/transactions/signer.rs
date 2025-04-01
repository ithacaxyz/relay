use super::{
    metrics::TransactionServiceMetrics,
    transaction::{PendingTransaction, RelayTransaction, TransactionStatus, TxId},
};
use crate::{
    error::StorageError,
    signers::DynSigner,
    storage::{RelayStorage, StorageApi},
    types::{ENTRYPOINT_NO_ERROR, EntryPoint},
};
use alloy::{
    consensus::{Transaction, TxEip1559, TxEnvelope, TypedTransaction},
    eips::{BlockId, Encodable2718},
    network::{Ethereum, EthereumWallet, NetworkWallet},
    primitives::{Address, Bytes},
    providers::{
        DynProvider, PendingTransactionConfig, PendingTransactionError, Provider,
        utils::{
            EIP1559_FEE_ESTIMATION_PAST_BLOCKS, EIP1559_FEE_ESTIMATION_REWARD_PERCENTILE,
            Eip1559Estimator,
        },
    },
    rpc::types::TransactionRequest,
    sol_types::SolCall,
    transports::{RpcError, TransportErrorKind, TransportResult},
};
use chrono::Utc;
use futures_util::{StreamExt, lock::Mutex, stream::FuturesUnordered};
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::mpsc;
use tracing::error;

/// Errors that may occur while sending a transaction.
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    /// The userop reverted when trying transaction.
    #[error("op reverted: {revert_reason}")]
    OpRevert {
        /// The error code returned by the entrypoint.
        revert_reason: Bytes,
    },

    /// The transaction was dropped.
    #[error("transaction was dropped")]
    TxDropped,

    /// The growth of the gas fees exceeded the amount we are ready to pay
    #[error("transaction underpriced")]
    FeesTooHigh,

    /// Error occurred while signing transaction.
    #[error(transparent)]
    Sign(#[from] alloy::signers::Error),

    /// RPC error.
    #[error(transparent)]
    Rpc(#[from] RpcError<TransportErrorKind>),

    /// Storage error.
    #[error(transparent)]
    Storage(#[from] StorageError),

    /// Other errors.
    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl From<PendingTransactionError> for SignerError {
    fn from(value: PendingTransactionError) -> Self {
        match value {
            PendingTransactionError::TransportError(err) => Self::Rpc(err),
            err => Self::Other(Box::new(err)),
        }
    }
}

/// Messages accepted by the [`Signer`].
#[derive(Debug, Clone)]
pub enum SignerMessage {
    /// Message to send a transaction.
    SendTransaction(RelayTransaction),
}

/// Event emitted by the [`Signer`].
#[derive(Debug)]
pub enum SignerEvent {
    /// Status update for a transaction.
    TransactionStatus(TxId, TransactionStatus),
}

/// A signer responsible for signing and sending transactions on a single network.
#[derive(Debug)]
pub struct Signer {
    /// Provider used by the signer.
    provider: DynProvider,
    /// Inner [`EthereumWallet`] used to sign transactions.
    wallet: EthereumWallet,
    /// Cached chain id of the provider.
    chain_id: u64,
    /// Estimated block time.
    block_time: Duration,
    /// Nonce of thes signer.
    nonce: Mutex<u64>,
    /// Channel to send signer events to.
    events_tx: mpsc::UnboundedSender<SignerEvent>,
    /// Underlying storage.
    storage: RelayStorage,
    /// Metrics of the parent transaction service.
    metrics: Arc<TransactionServiceMetrics>,
}

impl Signer {
    /// Creates a new [`Signer`].
    pub async fn spawn(
        provider: DynProvider,
        signer: DynSigner,
        storage: RelayStorage,
        metrics: Arc<TransactionServiceMetrics>,
    ) -> TransportResult<SignerHandle> {
        let address = signer.address();
        let wallet = EthereumWallet::new(signer.0);

        let (nonce, chain_id, latest) = tokio::try_join!(
            provider.get_transaction_count(address).pending(),
            provider.get_chain_id(),
            provider.get_block(BlockId::latest())
        )?;

        // Heuristically estimate the block time.
        let block_time = {
            let latest = latest.ok_or(RpcError::NullResp)?;
            let length = 1000.min(latest.header.number - 1);
            let start = provider
                .get_block(BlockId::number(latest.header.number - length))
                .await?
                .ok_or(RpcError::NullResp)?;

            Duration::from_millis(
                1000 * (latest.header.timestamp - start.header.timestamp) / length,
            )
        };

        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let (events_tx, events_rx) = mpsc::unbounded_channel();

        let this = Self {
            provider,
            wallet,
            chain_id,
            block_time,
            nonce: Mutex::new(nonce),
            events_tx,
            storage,
            metrics,
        };

        let loaded_transactions = this
            .storage
            .read_pending_transactions(this.address(), this.chain_id)
            .await
            .expect("failed to read pending transactions");

        tokio::spawn(this.into_future(command_rx, loaded_transactions));

        Ok(SignerHandle { command_tx, events_rx })
    }

    /// Returns the signer address.
    pub fn address(&self) -> Address {
        NetworkWallet::<Ethereum>::default_signer_address(&self.wallet)
    }

    /// Sends a transaction status update.
    async fn update_tx_status(
        &self,
        tx: TxId,
        status: TransactionStatus,
    ) -> Result<(), StorageError> {
        self.storage.write_transaction_status(tx, &status).await?;
        let _ = self.events_tx.send(SignerEvent::TransactionStatus(tx, status));

        Ok(())
    }

    async fn validate_transaction(
        &self,
        mut tx: RelayTransaction,
    ) -> Result<RelayTransaction, SignerError> {
        // Set payment recipient to us
        tx.quote.ty_mut().op.paymentRecipient = self.address();

        let mut request: TransactionRequest = tx.build(0).into();
        // Unset nonce to avoid race condition.
        request.nonce = None;
        request.from = Some(self.address());

        // Try eth_call before committing to send the actual transaction
        self.provider
            .call(request)
            .await
            .and_then(|res| {
                EntryPoint::executeCall::abi_decode_returns(&res, true)
                    .map_err(TransportErrorKind::custom)
            })
            .map_err(SignerError::from)
            .and_then(|result| {
                if result.err != ENTRYPOINT_NO_ERROR {
                    return Err(SignerError::OpRevert { revert_reason: result.err.into() });
                }
                Ok(())
            })?;

        Ok(tx)
    }

    /// Broadcasts a given transaction.
    async fn send_transaction(&self, tx: TypedTransaction) -> Result<TxEnvelope, SignerError> {
        // Sign the transaction.
        let signed =
            NetworkWallet::<Ethereum>::sign_transaction_from(&self.wallet, self.address(), tx)
                .await?;

        let _ = self.provider.send_raw_transaction(&signed.encoded_2718()).await?;
        Ok(signed)
    }

    /// Waits for a pending transaction to be confirmed.
    ///
    /// Receives a mutable reference to [`SentTransaction`] and might potentially modify it when
    /// bumping the fees.
    async fn watch_transaction_inner(
        &self,
        tx: &mut PendingTransaction,
    ) -> Result<(), SignerError> {
        let mut retries = 0;

        loop {
            let handle = self
                .provider
                .watch_pending_transaction(
                    PendingTransactionConfig::new(tx.tx_hash())
                        .with_timeout(Some(self.block_time * 2)),
                )
                .await?;

            if handle.await.is_ok() {
                self.update_tx_status(tx.id(), TransactionStatus::Confirmed(tx.tx_hash())).await?;
                self.storage.remove_pending_transaction(tx.id()).await?;
                return Ok(());
            }

            if retries > 3 {
                return Err(SignerError::TxDropped);
            }

            let fee_history = self
                .provider
                .get_fee_history(
                    EIP1559_FEE_ESTIMATION_PAST_BLOCKS,
                    Default::default(),
                    &[EIP1559_FEE_ESTIMATION_REWARD_PERCENTILE],
                )
                .await?;

            let last_base_fee = fee_history.latest_block_base_fee().unwrap_or_default();

            let fee_estimate = Eip1559Estimator::default()
                .estimate(last_base_fee, &fee_history.reward.unwrap_or_default());

            // if the latest block base fee is higher than max_fee, we don't want to block on
            // waiting for it to go down
            if tx.sent.max_fee_per_gas() < last_base_fee {
                return Err(SignerError::FeesTooHigh);
            }

            // TODO: figure out a more reasonable condition here or whether we should just always
            // set max_priority_fee = max_fee
            if fee_estimate.max_priority_fee_per_gas
                > tx.sent.max_priority_fee_per_gas().unwrap_or(tx.sent.max_fee_per_gas()) * 11 / 10
            {
                // Fees went up, assume we need to bump them
                let new_tip_cap = fee_estimate.max_priority_fee_per_gas;

                // Ensure we can afford the bump given the current base fee
                if (tx.sent.max_fee_per_gas() - last_base_fee) < new_tip_cap {
                    return Err(SignerError::FeesTooHigh);
                }

                let mut typed = TypedTransaction::from(tx.sent.clone());
                match &mut typed {
                    TypedTransaction::Eip1559(tx) => tx.max_priority_fee_per_gas = new_tip_cap,
                    TypedTransaction::Eip7702(tx) => tx.max_priority_fee_per_gas = new_tip_cap,
                    _ => {}
                };

                tx.sent = self.send_transaction(typed).await?;
                self.update_tx_status(tx.id(), TransactionStatus::Pending(tx.tx_hash())).await?;
                self.storage.write_pending_transaction(tx).await?;
            } else if !self
                .provider
                .get_transaction_by_hash(tx.tx_hash())
                .await
                .is_ok_and(|tx| tx.is_some())
            {
                // The transaction was dropped, try to rebroadcast it.
                let _ = self.provider.send_raw_transaction(&tx.sent.encoded_2718()).await?;
                retries += 1;
            }
        }
    }

    /// Awaits the given [`PendingTransaction`] and watches it for status updates.
    async fn watch_transaction(&self, mut tx: PendingTransaction) -> Result<(), SignerError> {
        self.metrics.pending.increment(1);
        if let Err(err) = self.watch_transaction_inner(&mut tx).await {
            self.metrics.pending.decrement(1);
            self.update_tx_status(tx.id(), TransactionStatus::Failed(Arc::new(err))).await?;
            self.storage.remove_pending_transaction(tx.id()).await?;
            return self.close_nonce_gap(tx.sent.nonce()).await;
        }

        self.metrics
            .confirmation_time
            .record(Utc::now().signed_duration_since(tx.received_at).num_milliseconds() as f64);
        self.metrics.pending.decrement(1);

        Ok(())
    }

    /// Broadcasts a given transaction and waits for it to be confirmed, notifying `status_tx` on
    /// each status update.
    async fn send_and_watch_transaction(&self, tx: RelayTransaction) -> Result<(), SignerError> {
        let tx_id = tx.id;

        let tx = match self.validate_transaction(tx).await {
            Ok(tx) => tx,
            Err(err) => {
                self.update_tx_status(tx_id, TransactionStatus::Failed(Arc::new(err))).await?;
                return Ok(());
            }
        };

        // Choose nonce for the transaction.
        let nonce = {
            let mut nonce = self.nonce.lock().await;
            let current_nonce = *nonce;
            *nonce += 1;
            current_nonce
        };

        let sent = match self.send_transaction(tx.build(nonce)).await {
            Ok(sent) => sent,
            Err(err) => {
                self.update_tx_status(tx.id, TransactionStatus::Failed(Arc::new(err))).await?;

                // If no other transaction occupied the next nonce, we can just reset it.
                {
                    let mut lock = self.nonce.lock().await;
                    if *lock == nonce + 1 {
                        *lock = nonce;
                        return Ok(());
                    }
                }

                // Otherwise, we need to close the nonce gap.
                return self.close_nonce_gap(nonce).await;
            }
        };
        let tx = PendingTransaction { tx, sent, signer: self.address(), received_at: Utc::now() };

        self.update_tx_status(tx.id(), TransactionStatus::Pending(tx.tx_hash())).await?;
        self.storage.write_pending_transaction(&tx).await?;

        self.watch_transaction(tx).await
    }

    /// Closes the nonce gap by sending a dummy transaction to the signer.
    ///
    /// This can be called in 2 cases:
    ///     1. We failed to send a transaction. This is very unlikely, and if happens, hard to
    ///        recover as it most likely signals critical KMS or RPC failure.
    ///     2. We failed to wait for a transaction to be mined. This is more likely, and means that
    ///        transaction wa succesfuly broadcasted but never confirmed likely causing a nonce gap.
    async fn close_nonce_gap(&self, nonce: u64) -> Result<(), SignerError> {
        let fee_estimate = self.provider.estimate_eip1559_fees().await?;
        let tx = TypedTransaction::Eip1559(TxEip1559 {
            chain_id: self.chain_id,
            nonce,
            to: self.address().into(),
            gas_limit: 21000,
            max_priority_fee_per_gas: fee_estimate.max_priority_fee_per_gas,
            max_fee_per_gas: fee_estimate.max_fee_per_gas,
            ..Default::default()
        });

        let tx = self.send_transaction(tx).await?;
        // Give transaction 10 blocks to be mined.
        self.provider
            .watch_pending_transaction(
                PendingTransactionConfig::new(*tx.tx_hash())
                    .with_timeout(Some(self.block_time * 10)),
            )
            .await?
            .await?;

        Ok(())
    }

    /// Converts [`Signer`] into a future.
    async fn into_future(
        self,
        mut command_rx: mpsc::UnboundedReceiver<SignerMessage>,
        loaded_transactions: Vec<PendingTransaction>,
    ) {
        let mut pending: FuturesUnordered<Pin<Box<dyn Future<Output = _> + Send + '_>>> =
            FuturesUnordered::new();

        // Watch pending transactions that were loaded from storage
        for tx in loaded_transactions {
            pending.push(Box::pin(self.watch_transaction(tx)));
        }

        loop {
            tokio::select! {
                command = command_rx.recv() => if let Some(command) = command {
                    match command {
                        SignerMessage::SendTransaction(tx) => {
                            pending.push(Box::pin(self.send_and_watch_transaction(tx)))
                        }
                    }
                },
                Some(_) = pending.next() => {}
            }
        }
    }
}

/// Handle to interact with [`Signer`].
#[derive(Debug)]
pub struct SignerHandle {
    command_tx: mpsc::UnboundedSender<SignerMessage>,
    events_rx: mpsc::UnboundedReceiver<SignerEvent>,
}

impl SignerHandle {
    /// Sends a [`SignerMessage::SendTransaction`] to the [`Signer`].
    pub fn send_transaction(&self, tx: RelayTransaction) {
        let _ = self.command_tx.send(SignerMessage::SendTransaction(tx));
    }

    /// Polls for a signer event.
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<SignerEvent>> {
        self.events_rx.poll_recv(cx)
    }
}
