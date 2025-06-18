use super::{
    TransactionMonitoringHandle,
    fees::{FeeContext, FeesError, MIN_GAS_PRICE_BUMP},
    metrics::{SignerMetrics, TransactionServiceMetrics},
    transaction::{
        PendingTransaction, RelayTransaction, TransactionFailureReason, TransactionStatus, TxId,
    },
};
use crate::{
    config::TransactionServiceConfig,
    error::StorageError,
    signers::DynSigner,
    storage::{RelayStorage, StorageApi},
    transport::error::TransportErrExt,
    types::{
        ORCHESTRATOR_NO_ERROR,
        OrchestratorContract::{self, IntentExecuted},
    },
};
use alloy::{
    consensus::{Transaction, TxEip1559, TxEnvelope, TypedTransaction},
    eips::{BlockId, Encodable2718, eip1559::Eip1559Estimation},
    network::{Ethereum, EthereumWallet, NetworkWallet},
    primitives::{Address, Bytes, U256, uint},
    providers::{
        DynProvider, PendingTransactionError, Provider,
        utils::{EIP1559_FEE_ESTIMATION_PAST_BLOCKS, Eip1559Estimator},
    },
    rpc::types::{TransactionReceipt, TransactionRequest},
    sol_types::SolCall,
    transports::{RpcError, TransportErrorKind},
};
use chrono::Utc;
use eyre::{OptionExt, WrapErr};
use futures_util::{StreamExt, lock::Mutex, stream::FuturesUnordered, try_join};
use opentelemetry::trace::{SpanKind, TraceContextExt};
use std::{
    fmt::Display,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};
use tokio::{sync::mpsc, task::JoinSet};
use tracing::{Level, Span, debug, error, instrument, span, trace, warn};
use tracing_futures::Instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// Lower bound of gas a signer should be able to afford before getting paused until being funded.
const MIN_SIGNER_GAS: U256 = uint!(30_000_000_U256);

/// Errors that may occur while sending a transaction.
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    /// The intent reverted when trying transaction.
    #[error("intent reverted: {revert_reason}")]
    IntentRevert {
        /// The error code returned by the orchestrator.
        revert_reason: Bytes,
    },

    /// The transaction was dropped.
    #[error("transaction was dropped")]
    TxDropped,

    /// The transaction timed out while waiting for confirmation.
    #[error("timed out while waiting for confirmation")]
    TxTimeout,

    /// The growth of the gas fees exceeded the amount we are ready to pay
    #[error("transaction underpriced: {0}")]
    FeesTooHigh(#[from] FeesError),

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

/// State of [`Signer`].
#[derive(Debug)]
pub struct SignerInner {
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
    metrics: SignerMetrics,
    /// Whether the signer is paused.
    paused: AtomicBool,
    /// Configuration for the service.
    config: TransactionServiceConfig,
    /// Handle for monitoring pending transactions.
    monitor: TransactionMonitoringHandle,
}

/// A signer responsible for signing and sending transactions on a single network.
#[derive(Debug, Clone, derive_more::Deref)]
pub struct Signer {
    #[deref]
    inner: Arc<SignerInner>,
}

impl Signer {
    /// Creates a new [`Signer`].
    #[expect(clippy::too_many_arguments)]
    pub async fn new(
        id: SignerId,
        provider: DynProvider,
        signer: DynSigner,
        storage: RelayStorage,
        events_tx: mpsc::UnboundedSender<SignerEvent>,
        tx_metrics: Arc<TransactionServiceMetrics>,
        config: TransactionServiceConfig,
        monitor: TransactionMonitoringHandle,
    ) -> eyre::Result<Self> {
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
            let latest = latest.ok_or_eyre("couldn't fetch latest block")?;
            let length = 1000.min(latest.header.number - 1);
            let start = provider
                .get_block(BlockId::number(latest.header.number - length))
                .await?
                .ok_or_eyre("couldn't fetch block to estimate block time")?;

            Duration::from_millis(
                1000 * (latest.header.timestamp - start.header.timestamp) / length,
            )
        };

        let inner = SignerInner {
            id,
            provider,
            wallet,
            chain_id,
            block_time,
            nonce: Mutex::new(nonce),
            events_tx,
            storage,
            metrics: SignerMetrics::new(tx_metrics, address, chain_id),
            paused: AtomicBool::new(false),
            config,
            monitor,
        };
        Ok(Self { inner: Arc::new(inner) })
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
    #[instrument(skip_all)]
    async fn update_tx_status(
        &self,
        tx: TxId,
        status: TransactionStatus,
    ) -> Result<(), StorageError> {
        self.storage.write_transaction_status(tx, &status).await?;
        self.emit_event(SignerEvent::TransactionStatus(tx, status));

        Ok(())
    }

    /// Invoked when a transaction is confirmed.
    #[instrument(skip_all)]
    async fn on_confirmed_transaction(
        &self,
        tx: PendingTransaction,
        receipt: TransactionReceipt,
    ) -> Result<(), StorageError> {
        self.update_tx_status(tx.id(), TransactionStatus::Confirmed(Box::new(receipt.clone())))
            .await?;
        self.storage.remove_pending_transaction(tx.id()).await?;

        self.metrics
            .confirmation_time
            .record(Utc::now().signed_duration_since(tx.sent_at).num_milliseconds() as f64);
        self.metrics.pending.decrement(1);
        self.metrics
            .total_wait_time
            .record(Utc::now().signed_duration_since(tx.tx.received_at).num_milliseconds() as f64);

        // Spawn a task to record metrics.
        let this = self.clone();
        tokio::spawn(async move { this.record_confirmed_metrics(tx, receipt).await });

        Ok(())
    }

    /// Invoked when a transaction fails.
    #[instrument(skip_all)]
    async fn on_failed_transaction(
        &self,
        tx: TxId,
        err: impl TransactionFailureReason + 'static,
    ) -> Result<(), SignerError> {
        // Remove transaction from storage
        self.storage.remove_queued(tx).await?;
        self.storage.remove_pending_transaction(tx).await?;

        // Update status
        self.update_tx_status(tx, TransactionStatus::Failed(Arc::new(err))).await?;

        Ok(())
    }

    /// Fetches the [`FeeContext`].
    async fn get_fee_context(&self) -> Result<FeeContext, SignerError> {
        let fee_history = self
            .provider
            .get_fee_history(
                EIP1559_FEE_ESTIMATION_PAST_BLOCKS,
                Default::default(),
                &[self.config.priority_fee_percentile],
            )
            .await?;

        let last_base_fee = fee_history.latest_block_base_fee().unwrap_or_default();

        let fee_estimate = Eip1559Estimator::default()
            .estimate(last_base_fee, &fee_history.reward.unwrap_or_default());

        Ok(FeeContext {
            last_base_fee,
            recommended_priority_fee: fee_estimate.max_priority_fee_per_gas,
        })
    }

    #[instrument(skip_all)]
    async fn validate_transaction(
        &self,
        tx: &mut RelayTransaction,
        fees: Eip1559Estimation,
    ) -> Result<(), SignerError> {
        // Set payment recipient to us if it hasn't been set
        let payment_recipient = &mut tx.quote.output.paymentRecipient;
        if payment_recipient.is_zero() {
            *payment_recipient = self.address();
        }

        let mut request: TransactionRequest = tx.build(0, fees).into();
        // Unset nonce to avoid race condition.
        request.nonce = None;
        request.from = Some(self.address());

        // Try eth_call before committing to send the actual transaction
        self.provider
            .call(request.clone())
            .await
            .and_then(|res| {
                OrchestratorContract::executeCall::abi_decode_returns(&res)
                    .map_err(TransportErrorKind::custom)
            })
            .map_err(SignerError::from)
            .and_then(|result| {
                if result != ORCHESTRATOR_NO_ERROR {
                    return Err(SignerError::IntentRevert { revert_reason: result.into() });
                }
                Ok(())
            })
            .inspect_err(|err| {
                trace!(?err, ?request, "transaction simulation failed");
            })?;

        Ok(())
    }

    /// Signs a given transaction.
    #[instrument(skip_all)]
    async fn sign_transaction(&self, tx: TypedTransaction) -> Result<TxEnvelope, SignerError> {
        Ok(NetworkWallet::<Ethereum>::sign_transaction_from(&self.wallet, self.address(), tx)
            .await?)
    }

    /// Broadcasts a given transaction.
    #[instrument(skip_all)]
    async fn send_transaction(&self, tx: &TxEnvelope) -> Result<(), SignerError> {
        let _ = self
            .provider
            .send_raw_transaction(&tx.encoded_2718())
            .await
            .inspect(|_| {
                trace!(
                    tx_hash = %tx.hash(),
                    nonce = %tx.nonce(),
                    "Sent transaction"
                );
            })
            .inspect_err(|err| {
                error!(
                    tx_hash = %tx.hash(),
                    nonce = %tx.nonce(),
                    err = %err,
                    "Failed to send transaction"
                );
            })?;

        Ok(())
    }

    /// Waits for a pending transaction to be confirmed.
    ///
    /// Receives a mutable reference to [`SentTransaction`] and might potentially modify it when
    /// bumping the fees.
    async fn watch_transaction_inner(
        &self,
        tx: &mut PendingTransaction,
    ) -> Result<TransactionReceipt, SignerError> {
        let mut last_sent_at = Instant::now();

        loop {
            if last_sent_at.elapsed() >= self.config.transaction_timeout {
                error!(?tx, "Transaction timed out");
                return Err(SignerError::TxTimeout);
            }

            let mut handles = FuturesUnordered::new();
            for sent in &tx.sent {
                handles.push(self.monitor.watch_transaction(*sent.tx_hash(), self.block_time * 2));
            }

            while let Some(receipt_opt) = handles.next().await {
                if let Some(receipt) = receipt_opt {
                    return Ok(receipt);
                }
            }

            let fees = self.get_fee_context().await?;
            let best_tx = tx.best_tx();

            if let Some(new_fees) =
                fees.prepare_replacement(best_tx, tx.tx.max_fee_for_transaction())?
            {
                let new_tx = tx.tx.build(tx.nonce(), new_fees);
                let replacement = self.sign_transaction(new_tx).await?;
                self.storage.add_pending_envelope(tx.id(), &replacement).await?;
                self.send_transaction(&replacement).await?;
                self.metrics.replacements_sent.increment(1);
                self.update_tx_status(tx.id(), TransactionStatus::Pending(*replacement.tx_hash()))
                    .await?;
                tx.sent.push(replacement);
                last_sent_at = Instant::now();
            } else {
                trace!(tx_hash=%best_tx.tx_hash(), "was not able to wait for tx confirmation, attempting to resend");
                if let Err(err) = self.provider.send_raw_transaction(&best_tx.encoded_2718()).await
                {
                    if !err.is_already_known() {
                        debug!(%err, tx_hash=%best_tx.tx_hash(), "failed to resubmit transaction");
                    }
                }
            }
        }
    }

    /// Awaits the given [`PendingTransaction`] and watches it for status updates.
    #[instrument(skip_all, fields(tx_id = %tx.tx.id))]
    async fn watch_transaction(&self, mut tx: PendingTransaction) -> Result<(), SignerError> {
        Span::current().add_link(tx.tx.trace_context.span().span_context().clone());

        // todo: set parent span to context in pendingtx
        self.metrics.pending.increment(1);
        match self.watch_transaction_inner(&mut tx).await {
            Ok(receipt) => {
                self.on_confirmed_transaction(tx, receipt).await?;
            }
            Err(err) => {
                error!(%err, "failed to wait for transaction confirmation, closing nonce gap");

                // If we've failed to send the transaction, start closing the nonce gap to make sure
                // we occupy the chosen nonce.
                self.close_nonce_gap(tx.nonce(), Some(tx.fees())).await;

                // After making sure that the nonce is occupied, check if it was occupied by one of
                // the transactions sent before.
                for sent in &tx.sent {
                    if let Ok(Some(receipt)) =
                        self.provider.get_transaction_receipt(*sent.tx_hash()).await
                    {
                        if receipt.block_number.is_some() {
                            self.on_confirmed_transaction(tx, receipt).await?;
                            return Ok(());
                        }
                    }
                }

                // None of the sent transactions confirmed, mark transaction as failed.
                self.metrics.pending.decrement(1);
                self.on_failed_transaction(tx.id(), err).await?;
            }
        }

        Ok(())
    }

    /// Broadcasts a given transaction and waits for it to be confirmed, notifying `status_tx` on
    /// each status update.
    async fn send_and_watch_transaction(
        &self,
        mut tx: RelayTransaction,
    ) -> Result<(), SignerError> {
        self.metrics
            .time_in_queue
            .record(Utc::now().signed_duration_since(tx.received_at).num_milliseconds() as f64);

        // Fetch the fees for the first transaction.
        let fees = match self
            .get_fee_context()
            .await
            .and_then(|fees| Ok(fees.fees_for_new_transaction(tx.max_fee_for_transaction())?))
        {
            Ok(fees) => fees,
            Err(err) => {
                self.on_failed_transaction(tx.id, err).await?;
                return Ok(());
            }
        };

        // Validate the transaction.
        if let Err(err) = self.validate_transaction(&mut tx, fees).await {
            self.on_failed_transaction(tx.id, err).await?;
            return Ok(());
        }

        // Choose nonce for the transaction.
        let nonce = {
            let mut nonce = self.nonce.lock().await;
            let current_nonce = *nonce;
            *nonce += 1;
            current_nonce
        };

        let tx_id = tx.id;

        let try_send = async {
            // sign transaction
            let signed = self.sign_transaction(tx.build(nonce, fees)).await?;

            // write pending transaction to storage first to avoid race condition
            let tx = PendingTransaction {
                tx,
                sent: vec![signed.clone()],
                signer: self.address(),
                sent_at: Utc::now(),
            };
            self.storage.replace_queued_tx_with_pending(&tx).await?;

            // send transaction and update status
            self.send_transaction(&signed).await?;
            self.update_tx_status(tx.id(), TransactionStatus::Pending(*signed.hash())).await?;

            Ok::<_, SignerError>(tx)
        };

        match try_send.await {
            Ok(tx) => self.watch_transaction(tx).await,
            Err(err) => {
                error!(%err, "failed to send a transaction");

                self.on_failed_transaction(tx_id, err).await?;

                // If no other transaction occupied the next nonce, we can just reset it.
                {
                    let mut lock = self.nonce.lock().await;
                    if *lock == nonce + 1 {
                        *lock = nonce;
                        return Ok(());
                    }
                }

                // Otherwise, we need to close the nonce gap.
                self.close_nonce_gap(nonce, None).await;

                Ok(())
            }
        }
    }

    /// Closes the nonce gap by sending a dummy transaction to the signer.
    ///
    /// This can be called in 2 cases:
    ///     1. We failed to send a transaction. This is very unlikely, and if happens, hard to
    ///        recover as it most likely signals critical KMS or RPC failure.
    ///     2. We failed to wait for a transaction to be mined. This is more likely, and means that
    ///        transaction wa succesfuly broadcasted but never confirmed likely causing a nonce gap.
    #[instrument(skip_all)]
    async fn close_nonce_gap(&self, nonce: u64, min_fees: Option<Eip1559Estimation>) {
        self.metrics.detected_nonce_gaps.increment(1);

        let try_close = || async {
            let fee_estimate = self.provider.estimate_eip1559_fees().await?;
            let (max_fee, max_tip) = if let Some(min_fees) = min_fees {
                // If we are provided with `min_fees`, this means, we are going to replace some
                // existing transaction. Nodes usually require us to bump the fees by some margin to
                // replace a transaction, so we are enforcing that assigned fees are not too low.
                let min_fee = min_fees.max_fee_per_gas * (100 + MIN_GAS_PRICE_BUMP) / 100;
                let min_tip = min_fees.max_priority_fee_per_gas * (100 + MIN_GAS_PRICE_BUMP) / 100;

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

            let tx = self.sign_transaction(tx).await?;
            self.send_transaction(&tx).await?;
            // Give transaction 10 blocks to be mined.
            if self.monitor.watch_transaction(*tx.tx_hash(), self.block_time * 10).await.is_none() {
                return Err(SignerError::TxTimeout);
            }

            Ok::<_, SignerError>(())
        };

        loop {
            debug!(%nonce, "Attempting to close nonce gap");

            let Err(err) = try_close().await else { break };

            error!(%err, %nonce, "Failed to close nonce gap");

            if let Ok(latest_nonce) = self.provider.get_transaction_count(self.address()).await {
                if latest_nonce > nonce {
                    warn!("nonce gap was closed by a different transaction");
                    break;
                }
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        debug!(%nonce, "Closed nonce gap");
        self.metrics.closed_nonce_gaps.increment(1);
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
                    address=?self.address(),
                    ?balance,
                    max_fee_per_gas = ?fees.max_fee_per_gas,
                    ?min_balance,
                    "signer balance is too low, pausing"
                );
                self.emit_event(SignerEvent::PauseSigner(self.id()));
                self.paused.store(true, Ordering::Relaxed);
            }
        } else if balance >= min_balance {
            debug!("signer balance is sufficient, re-activating");
            self.emit_event(SignerEvent::ReActive(self.id()));
            self.paused.store(false, Ordering::Relaxed);
        }

        Ok(())
    }

    /// Fetches receipt of a confirmed transaction and records metrics.
    async fn record_confirmed_metrics(&self, tx: PendingTransaction, receipt: TransactionReceipt) {
        let tx_hash = receipt.transaction_hash;

        self.metrics.gas_spent.increment(receipt.gas_used as f64);
        self.metrics.native_spent.increment(f64::from(
            U256::from(receipt.gas_used) * U256::from(receipt.effective_gas_price),
        ));

        if !receipt.status() {
            warn!(%tx_hash, "transaction reverted");
            self.metrics.failed_intents.increment(1);
            return;
        }

        let Some(event) = IntentExecuted::try_from_receipt(&receipt) else {
            warn!(%tx_hash, "failed to find IntentExecuted event in receipt");
            self.metrics.failed_intents.increment(1);
            return;
        };

        if event.err != ORCHESTRATOR_NO_ERROR {
            warn!(%tx_hash, err = %event.err, "intent failed on-chain");
            self.metrics.failed_intents.increment(1);
            return;
        }

        if let Some(included_at_block) = receipt.block_number {
            if let Some(block) =
                self.provider.get_block(included_at_block.into()).await.ok().flatten()
            {
                let submitted_at = tx.sent_at.timestamp() as u64;
                let included_at = block.header.timestamp;

                let submitted_at_block = async {
                    let block_time = self.block_time.as_millis();

                    // Firsly try guessing the block based on block time.
                    let first_guess = if block_time == 0 {
                        included_at_block
                    } else {
                        included_at_block.saturating_sub(
                            ((included_at.saturating_sub(submitted_at)) as u128 * 1000 / block_time)
                                as u64,
                        )
                    };

                    // Follow the chain until we find a block after the submission time.
                    let mut block =
                        self.provider.get_block(first_guess.into()).await.ok().flatten()?;
                    while block.header.timestamp <= submitted_at {
                        block = self
                            .provider
                            .get_block((block.header.number + 1).into())
                            .await
                            .ok()
                            .flatten()?;
                    }

                    // Go back until there are earlier blocks mined after the submission time.
                    let mut prev_block = self
                        .provider
                        .get_block((block.header.number - 1).into())
                        .await
                        .ok()
                        .flatten()?;
                    while prev_block.header.timestamp > submitted_at {
                        block = prev_block;
                        prev_block = self
                            .provider
                            .get_block((block.header.number - 1).into())
                            .await
                            .ok()
                            .flatten()?;
                    }

                    Some(block.header.number)
                }
                .await;

                if let Some(submitted_at_block) = submitted_at_block {
                    self.metrics
                        .blocks_until_inclusion
                        .record((included_at_block - submitted_at_block + 1) as f64);
                }
            }
        }

        self.metrics.successful_intents.increment(1);
    }

    /// Spawns a new [`Signer`] instance. Returns [`SignerTask`] and the pending transactions that
    /// were loaded on startup.
    pub async fn into_future(self) -> eyre::Result<(SignerTask, Vec<PendingTransaction>)> {
        let loaded_transactions = self
            .storage
            .read_pending_transactions(self.address(), self.chain_id)
            .await
            .wrap_err("failed to read pending transactions")?;

        // Make sure that loaded transactions are not getting overriden by the new ones
        {
            let mut lock = self.nonce.lock().await;
            if let Some(nonce) = loaded_transactions.iter().map(|tx| tx.nonce() + 1).max() {
                if nonce > *lock {
                    *lock = nonce;
                }
            }
        }

        let latest_nonce = self.provider.get_transaction_count(self.address()).await?;
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

        self.record_and_check_balance().await?;

        if self.is_paused() && (!gapped_nonces.is_empty() || !loaded_transactions.is_empty()) {
            warn!("signer is paused, but there are pending transactions loaded on startup");
        }

        let mut pending = JoinSet::new();
        let mut maintenance = JoinSet::new();

        for nonce in latest_nonce..*self.nonce.lock().await {
            if !loaded_transactions.iter().any(|tx| tx.nonce() == nonce) {
                warn!(%nonce, "nonce gap on startup");
                let this = self.clone();
                pending.spawn(async move {
                    this.close_nonce_gap(nonce, None).await;
                    Ok(())
                });
            }
        }

        // Watch pending transactions that were loaded from storage
        for tx in loaded_transactions.iter().cloned() {
            let signer = self.clone();
            pending.spawn(async move { signer.watch_transaction(tx).await });
        }

        // Create a never ending task that checks if on-chain nonce has diverged from local
        // nonce
        let this = self.clone();
        maintenance.spawn(async move {
            loop {
                tokio::time::sleep(this.config.nonce_check_interval).await;

                if let Ok(nonce) =
                    this.provider.get_transaction_count(this.address()).pending().await
                {
                    this.metrics.nonce.absolute(nonce);
                    let mut lock = this.nonce.lock().await;
                    if nonce > *lock {
                        warn!(%nonce, "on-chain nonce is ahead of local");
                        *lock = nonce;
                    }
                }
            }
        });

        // create a never ending task that checks signer balance.
        let this = self.clone();
        maintenance.spawn(async move {
            loop {
                tokio::time::sleep(this.config.balance_check_interval).await;

                if let Err(err) = this.record_and_check_balance().await {
                    warn!(%err, "failed to check signer balance");
                }
            }
        });

        Ok((
            SignerTask { signer: self, pending, _maintenance: maintenance, waker: None },
            loaded_transactions,
        ))
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
        write!(f, "Signer({})", self.0)
    }
}

/// A never ending future operating on [`Signer`] and handling transactions sending.
#[derive(derive_more::Debug)]
pub struct SignerTask {
    /// The signer instance.
    signer: Signer,
    /// All currently pending tasks. Those include pending transactions and nonce gap closing
    /// tasks.
    pending: JoinSet<Result<(), SignerError>>,
    /// All running maintenance tasks. Those are never ending futures that are performing various
    /// checks and potentially modify the signer state.
    ///
    /// Right now those include nonce gaps detection and balance checks.
    ///
    /// We don't poll this [`JoinSet`] as it will never yield anything and simply keep it to make
    /// sure the tasks are aborted once [`SignerTask`] is dropped.
    _maintenance: JoinSet<()>,
    /// Waker used to wake the signer task when new transactions are pushed.
    waker: Option<Waker>,
}

impl SignerTask {
    /// Pushes a new traаnsaction to the signer.
    ///
    /// Note; the transaction sending future is not polled until the [`SignerTask`] is polled.
    pub fn push_transaction(&mut self, tx: RelayTransaction) {
        let signer = self.signer.clone();
        self.pending.spawn(async move {
            let span = span!(
                Level::INFO,
                "process tx",
                otel.kind = ?SpanKind::Consumer,
                messaging.system = "pg",
                messaging.destination.name = "tx",
                messaging.operation.name = "consume",
                messaging.operation.type = "process",
                messaging.message.id = %tx.id,
            );
            span.add_link(tx.trace_context.span().span_context().clone());

            signer.send_and_watch_transaction(tx).instrument(span).await
        });
        if let Some(waker) = &self.waker {
            waker.wake_by_ref();
        }
    }

    /// Returns the number of pending transactions currently being processed by the signer.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Returns the current capacity of the signer.
    pub fn capacity(&self) -> usize {
        if self.is_paused() {
            0
        } else {
            self.signer.config.max_transactions_per_signer.saturating_sub(self.pending.len())
        }
    }

    /// Returns `true` if the signer is paused.
    pub fn is_paused(&self) -> bool {
        self.signer.is_paused()
    }
}

impl Future for SignerTask {
    type Output = ();

    #[instrument(name = "signer", skip_all, fields(address = ?self.signer.address(), chain_id = self.signer.chain_id()))]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let instant = Instant::now();

        let SignerTask { signer, pending, _maintenance: _, waker } = self.get_mut();

        *waker = Some(cx.waker().clone());

        while let Poll::Ready(Some(result)) = pending.poll_join_next(cx) {
            if !matches!(result, Ok(Ok(_))) {
                error!("signer task failed: {:?}", result);
            }
        }

        signer.metrics.poll_duration.record(instant.elapsed().as_nanos() as f64);

        Poll::Pending
    }
}
