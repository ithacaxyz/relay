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
    eips::{BlockId, Encodable2718, eip1559::Eip1559Estimation},
    network::{Ethereum, EthereumWallet, NetworkWallet},
    primitives::{Address, Bytes, U256, uint},
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
use futures_util::{StreamExt, lock::Mutex, stream::FuturesUnordered, try_join};
use std::{
    collections::VecDeque,
    fmt::Display,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::mpsc;
use tracing::{Instrument, debug, error, trace, warn};

/// Maximum number of pending transactions allowed per a single signer.
const MAX_PENDING_TRANSACTIONS: usize = 16;

/// Price bump for nonce gap transactions.
const NONCE_GAP_PRICE_BUMP: u128 = 20;

/// Lower bound of gas a signer should be able to afford before getting paused until being funded.
const MIN_SIGNER_GAS: U256 = uint!(30_000_000_U256);

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
    /// Pauses a signer.
    PauseSigner(SignerId),
    /// Reactivates a signer
    ReActive(SignerId),
}

/// A signer responsible for signing and sending transactions on a single network.
#[derive(Debug)]
pub struct Signer {
    /// The unique identifier of this signer service.
    id: SignerId,
    /// Provider used by the signer.
    provider: DynProvider,
    /// Inner [`EthereumWallet`] used to sign transactions.
    wallet: EthereumWallet,
    /// Cached chain id of the provider.
    chain_id: u64,
    /// Estimated block time.
    block_time: Duration,
    /// Nonce of this signer.
    nonce: Mutex<u64>,
    /// Channel to send signer events to.
    events_tx: mpsc::UnboundedSender<SignerEvent>,
    /// Underlying storage.
    storage: RelayStorage,
    /// Metrics of the parent transaction service.
    metrics: Arc<TransactionServiceMetrics>,
    /// Whether the signer is paused.
    paused: AtomicBool,
}

impl Signer {
    /// Creates a new [`Signer`].
    pub async fn new(
        id: SignerId,
        provider: DynProvider,
        signer: DynSigner,
        storage: RelayStorage,
        events_tx: mpsc::UnboundedSender<SignerEvent>,
        metrics: Arc<TransactionServiceMetrics>,
    ) -> TransportResult<Self> {
        let address = signer.address();
        let wallet = EthereumWallet::new(signer.0);

        // fetch account info
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

        let this = Self {
            id,
            provider,
            wallet,
            chain_id,
            block_time,
            nonce: Mutex::new(nonce),
            events_tx,
            storage,
            metrics,
            paused: AtomicBool::new(false),
        };
        Ok(this)
    }

    /// Returns the id of this [`Signer`].
    pub fn id(&self) -> SignerId {
        self.id
    }

    /// Returns the signer address.
    pub fn address(&self) -> Address {
        NetworkWallet::<Ethereum>::default_signer_address(&self.wallet)
    }

    /// Returns the chain id.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Emits an event.
    fn emit_event(&self, event: SignerEvent) {
        let _ = self.events_tx.send(event);
    }

    /// Returns whether the signer is paused.
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }

    /// Sends a transaction status update.
    async fn update_tx_status(
        &self,
        tx: TxId,
        status: TransactionStatus,
    ) -> Result<(), StorageError> {
        self.storage.write_transaction_status(tx, &status).await?;
        self.emit_event(SignerEvent::TransactionStatus(tx, status));

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

        let _ = self
            .provider
            .send_raw_transaction(&signed.encoded_2718())
            .await
            .inspect(|_| {
                trace!(
                    tx_hash = %signed.hash(),
                    nonce = %signed.nonce(),
                    "Sent transaction"
                );
            })
            .inspect_err(|err| {
                error!(
                    tx_hash = %signed.hash(),
                    nonce = %signed.nonce(),
                    err = %err,
                    "Failed to send transaction"
                );
            })?;

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
            return self.close_nonce_gap(tx.sent.nonce(), Some(tx.fees())).await;
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
                return self.close_nonce_gap(nonce, None).await;
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
    async fn close_nonce_gap(
        &self,
        nonce: u64,
        min_fees: Option<Eip1559Estimation>,
    ) -> Result<(), SignerError> {
        let try_close = || async {
            let fee_estimate = self.provider.estimate_eip1559_fees().await?;
            let (max_fee, max_tip) = if let Some(min_fees) = min_fees {
                // If we are provided with `min_fees`, this means, we are going to replace some
                // existing transaction. Nodes usually require us to bump the fees by some margin to
                // replace a transaction, so we are enforcing that assigned fees are not too low.
                let min_fee = min_fees.max_fee_per_gas * (100 + NONCE_GAP_PRICE_BUMP) / 100;
                let min_tip =
                    min_fees.max_priority_fee_per_gas * (100 + NONCE_GAP_PRICE_BUMP) / 100;

                (
                    min_fee.max(fee_estimate.max_fee_per_gas),
                    min_tip.max(fee_estimate.max_priority_fee_per_gas),
                )
            } else {
                (fee_estimate.max_fee_per_gas, fee_estimate.max_priority_fee_per_gas)
            };

            let tx = TypedTransaction::Eip1559(TxEip1559 {
                chain_id: self.chain_id,
                nonce,
                to: self.address().into(),
                gas_limit: 21000,
                max_priority_fee_per_gas: max_tip,
                max_fee_per_gas: max_fee,
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

            Ok::<_, SignerError>(())
        };

        loop {
            debug!(%nonce, "Attempting to close nonce gap");

            let Err(err) = try_close().await else { break };

            error!(%err, %nonce, "Failed to close nonce gap");

            if self.provider.get_transaction_count(self.address()).await? >= nonce {
                warn!("nonce gap was closed by a different transaction");
                break;
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        debug!(%nonce, "Closed nonce gap");

        Ok(())
    }

    /// Fetches the current signer balance and checks if the signer should be paused/unpaused.
    async fn record_and_check_balance(&self) -> Result<(), SignerError> {
        let (balance, fees) = try_join!(
            self.provider.get_balance(self.address()).into_future(),
            self.provider.estimate_eip1559_fees()
        )?;

        let min_balance = MIN_SIGNER_GAS * U256::from(fees.max_fee_per_gas);

        if !self.is_paused() {
            if balance < min_balance {
                warn!(
                    ?balance,
                    max_fee_per_gas = ?fees.max_fee_per_gas,
                    ?min_balance,
                    "signer balance is too low, pausing"
                );
                self.emit_event(SignerEvent::PauseSigner(self.id()));
                self.paused.store(true, Ordering::Relaxed);
            }
        } else if balance >= min_balance {
            self.emit_event(SignerEvent::ReActive(self.id()));
            self.paused.store(false, Ordering::Relaxed);
        }

        Ok(())
    }

    /// Spawns a new [`Signer`] instance.
    pub async fn spawn(self) -> SignerHandle {
        let (command_tx, mut command_rx) = mpsc::unbounded_channel();

        let loaded_transactions = self
            .storage
            .read_pending_transactions(self.address(), self.chain_id)
            .await
            .expect("failed to read pending transactions");

        let latest_nonce = self.provider.get_transaction_count(self.address()).await.unwrap();
        let gapped_nonces = (latest_nonce..*self.nonce.lock().await)
            .filter(|nonce| {
                if !loaded_transactions.iter().any(|tx| tx.nonce() == *nonce) {
                    warn!(%nonce, "nonce gap on startup");
                    true
                } else {
                    false
                }
            })
            .collect::<Vec<_>>();

        self.record_and_check_balance().await.expect("failed initial balance check");

        if self.is_paused() && (!gapped_nonces.is_empty() || !loaded_transactions.is_empty()) {
            warn!("signer is paused, but there are pending transactions loaded on startup");
        }

        let span = tracing::debug_span!(
            "signer",
            address = ?self.address(),
            chain_id = self.chain_id()
        );

        let fut = async move {
            let mut pending: FuturesUnordered<Pin<Box<dyn Future<Output = _> + Send + '_>>> =
                FuturesUnordered::new();
            let mut queued = VecDeque::new();

            // Handle the nonce gaps
            for nonce in gapped_nonces {
                pending.push(Box::pin(self.close_nonce_gap(nonce, None)));
            }

            // Watch pending transactions that were loaded from storage
            for tx in loaded_transactions {
                pending.push(Box::pin(self.watch_transaction(tx)));
            }

            // Create a never ending task that checks if on-chain nonce has diverged from local
            // nonce
            let mut nonce_check = Box::pin(async {
                loop {
                    tokio::time::sleep(Duration::from_secs(60)).await;

                    if let Ok(nonce) =
                        self.provider.get_transaction_count(self.address()).pending().await
                    {
                        let mut lock = self.nonce.lock().await;
                        if nonce > *lock {
                            warn!(%nonce, "on-chain nonce is ahead of local");
                            *lock = nonce;
                        }
                    }
                }
            });

            // create a never ending task that checks signer balance.
            let mut balance_check = Box::pin(async {
                loop {
                    tokio::time::sleep(Duration::from_secs(5)).await;

                    if let Err(err) = self.record_and_check_balance().await {
                        warn!(%err, "failed to check signer balance");
                    }
                }
            });

            loop {
                tokio::select! {
                    command = command_rx.recv() => if let Some(command) = command {
                        match command {
                            SignerMessage::SendTransaction(tx) => {
                                if pending.len() < MAX_PENDING_TRANSACTIONS {
                                    // If we have capacity for another transaction, send it now.
                                    pending.push(Box::pin(self.send_and_watch_transaction(tx)))
                                } else {
                                    // Otherwise, queue it for later.
                                    queued.push_back(tx);
                                }
                            }
                        }
                    },
                    Some(_) = pending.next() => {
                        if pending.len() < MAX_PENDING_TRANSACTIONS {
                            // If we have any queued transactions, send them now.
                            if let Some(tx) = queued.pop_front() {
                                pending.push(Box::pin(self.send_and_watch_transaction(tx)))
                            }
                        }
                    }
                    // poll the nonce check task
                    _ = &mut nonce_check => {}
                    // poll the balance check task
                    _ = &mut balance_check => {}
                }
            }
        };

        tokio::spawn(fut.instrument(span));

        SignerHandle { to_signer: command_tx }
    }
}

/// A unique identifier for one [`Signer`]
#[derive(Debug, Clone, Eq, PartialEq, Copy, Hash)]
pub struct SignerId(u64);

impl SignerId {
    /// Creates a new identifier.
    pub const fn new(id: u64) -> Self {
        Self(id)
    }
}

impl Display for SignerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Singer({})", self.0)
    }
}

/// Handle to interact with [`Signer`].
#[derive(Debug)]
pub struct SignerHandle {
    /// Command channel to send
    pub to_signer: mpsc::UnboundedSender<SignerMessage>,
}

impl SignerHandle {
    /// Sends a [`SignerMessage::SendTransaction`] to the [`Signer`].
    pub fn send_transaction(&self, tx: RelayTransaction) {
        let _ = self.to_signer.send(SignerMessage::SendTransaction(tx));
    }
}
