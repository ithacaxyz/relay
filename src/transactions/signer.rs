use super::transaction::{RelayTransaction, TransactionStatus};
use crate::{
    signers::DynSigner,
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
use futures_util::{StreamExt, lock::Mutex, stream::FuturesUnordered};
use std::{sync::Arc, time::Duration};
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
    #[error("fees to high")]
    FeesTooHigh,

    /// Error occurred while signing transaction.
    #[error(transparent)]
    Sign(#[from] alloy::signers::Error),

    /// RPC error.
    #[error(transparent)]
    Rpc(#[from] RpcError<TransportErrorKind>),

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
    SendTransaction {
        /// The transaction to send.
        tx: RelayTransaction,
        /// A channel to send transaction status updates to.
        status_tx: mpsc::UnboundedSender<TransactionStatus>,
    },
}

/// A signer responsible for signing and sending transactions on a single network.
#[derive(Debug, Clone)]
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
    nonce: Arc<Mutex<u64>>,
}

impl Signer {
    /// Creates a new [`Signer`].
    pub async fn new(provider: DynProvider, signer: DynSigner) -> TransportResult<Self> {
        let address = signer.address();
        let wallet = EthereumWallet::new(signer.0);

        let (nonce, chain_id, latest) = tokio::try_join!(
            provider.get_transaction_count(address).pending(),
            provider.get_chain_id(),
            provider.get_block(BlockId::latest())
        )?;

        let block_time = {
            let latest = latest.ok_or(RpcError::NullResp)?;
            let length = 1000.min(latest.header.number - 1);
            let start = provider
                .get_block(BlockId::number(latest.header.number - length))
                .await?
                .ok_or(RpcError::NullResp)?;

            Duration::from_millis(1000 * latest.header.timestamp - start.header.timestamp / length)
        };

        Ok(Self { provider, wallet, chain_id, block_time, nonce: Arc::new(Mutex::new(nonce)) })
    }

    /// Returns the signer address.
    pub fn address(&self) -> Address {
        NetworkWallet::<Ethereum>::default_signer_address(&self.wallet)
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
    async fn watch_transaction(
        &self,
        pending: &mut TxEnvelope,
        status_tx: &mut mpsc::UnboundedSender<TransactionStatus>,
    ) -> Result<(), SignerError> {
        let mut retries = 0;

        loop {
            let handle = self
                .provider
                .watch_pending_transaction(
                    PendingTransactionConfig::new(*pending.tx_hash())
                        .with_timeout(Some(self.block_time * 2)),
                )
                .await?;

            if handle.await.is_ok() {
                let _ = status_tx.send(TransactionStatus::Confirmed(*pending.tx_hash()));
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

            // TODO: figure out a more reasonable condition here or whether we should just always
            // set max_priority_fee = max_fee
            if fee_estimate.max_priority_fee_per_gas
                > pending.max_priority_fee_per_gas().unwrap_or(pending.max_fee_per_gas()) * 11 / 10
            {
                // Fees went up, assume we need to bump them
                let new_tip_cap = fee_estimate.max_priority_fee_per_gas;

                // Ensure we can afford the bump given the current base fee
                if (pending.max_fee_per_gas() - last_base_fee) < new_tip_cap {
                    return Err(SignerError::FeesTooHigh);
                }

                let mut typed = TypedTransaction::from(pending.clone());
                match &mut typed {
                    TypedTransaction::Eip1559(tx) => tx.max_priority_fee_per_gas = new_tip_cap,
                    TypedTransaction::Eip7702(tx) => tx.max_priority_fee_per_gas = new_tip_cap,
                    _ => {}
                };

                *pending = self.send_transaction(typed).await?;
                let _ = status_tx.send(TransactionStatus::Pending(*pending.tx_hash()));
            } else if !self
                .provider
                .get_transaction_by_hash(*pending.tx_hash())
                .await
                .is_ok_and(|tx| tx.is_some())
            {
                // The transaction was dropped, try to rebroadcast it.
                let _ = self.provider.send_raw_transaction(&pending.encoded_2718()).await?;
                retries += 1;
            }
        }
    }

    /// Broadcasts a given transaction and waits for it to be confirmed, notifying `status_tx` on
    /// each status update.
    async fn send_and_watch_transaction(
        &self,
        tx: RelayTransaction,
        mut status_tx: mpsc::UnboundedSender<TransactionStatus>,
    ) -> Result<(), SignerError> {
        let tx = match self.validate_transaction(tx).await {
            Ok(tx) => tx,
            Err(err) => {
                let _ = status_tx.send(TransactionStatus::Failed(Arc::new(err)));
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

        let mut sent = match self.send_transaction(tx.build(nonce)).await {
            Ok(sent) => sent,
            Err(err) => {
                let _ = status_tx.send(TransactionStatus::Failed(Arc::new(err)));

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
        let _ = status_tx.send(TransactionStatus::Pending(*sent.tx_hash()));

        if let Err(err) = self.watch_transaction(&mut sent, &mut status_tx).await {
            let _ = status_tx.send(TransactionStatus::Failed(Arc::new(err)));
            return self.close_nonce_gap(nonce).await;
        }

        Ok(())
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

    /// Spawns a new [`Signer`].
    pub fn spawn(self) -> SignerHandle {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        tokio::spawn(self.into_future(command_rx));
        SignerHandle { command_tx }
    }

    /// Converts [`Signer`] into a future.
    async fn into_future(self, mut command_rx: mpsc::UnboundedReceiver<SignerMessage>) {
        let mut pending = FuturesUnordered::new();

        loop {
            tokio::select! {
                command = command_rx.recv() => if let Some(command) = command {
                    match command {
                        SignerMessage::SendTransaction { tx, status_tx } => {
                            pending.push(self.send_and_watch_transaction(tx, status_tx))
                        }
                    }
                },
                Some(_) = pending.next() => {}
            }
        }
    }
}

/// Handle to interact with [`Signer`].
#[derive(Debug, Clone)]
pub struct SignerHandle {
    command_tx: mpsc::UnboundedSender<SignerMessage>,
}

impl SignerHandle {
    /// Sends a [`SignerMessage::SendTransaction`] to the [`Signer`].
    pub fn send_transaction(
        &self,
        tx: RelayTransaction,
    ) -> mpsc::UnboundedReceiver<TransactionStatus> {
        let (status_tx, status_rx) = mpsc::unbounded_channel();
        let _ = self.command_tx.send(SignerMessage::SendTransaction { tx, status_tx });
        status_rx
    }
}
