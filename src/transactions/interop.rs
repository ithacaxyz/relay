use super::{
    RelayTransaction, TransactionFailureReason, TransactionServiceHandle, TransactionStatus,
};
use crate::{
    error::StorageError,
    liquidity::{LiquidityTracker, LiquidityTrackerError},
    types::{rpc::BundleId, OrchestratorContract::IntentExecuted, IERC20},
};
use alloy::{
    primitives::{Address, BlockNumber, ChainId, U256, map::HashMap},
    providers::{DynProvider, MulticallError, Provider},
    rpc::types::TransactionReceipt,
};
use futures_util::future::JoinAll;
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::sync::mpsc;
use tracing::{error, instrument};

/// Bundle of transactions for cross-chain execution.
#[derive(Debug, Clone)]
pub struct InteropBundle {
    /// Unique identifier for the bundle.
    pub id: BundleId,
    /// Source chain transactions.
    pub src_transactions: Vec<RelayTransaction>,
    /// Destination chain transactions. Those can't be sent until all source chain transactions
    /// are confirmed.
    pub dst_transactions: Vec<RelayTransaction>,
}

impl InteropBundle {
    /// Creates a new interop bundle.
    pub fn new(
        id: BundleId,
        src_transactions: Vec<RelayTransaction>,
        dst_transactions: Vec<RelayTransaction>,
    ) -> Self {
        Self { id, src_transactions, dst_transactions }
    }
}

/// Errors that can occur during interop bundle processing.
#[derive(Debug, thiserror::Error)]
enum InteropBundleError {
    /// Transaction failed.
    #[error("transaction failed: {0}")]
    TransactionError(Arc<dyn TransactionFailureReason>),
    /// Errors returned by [`LiquidityTracker`].
    #[error(transparent)]
    Liquidity(#[from] LiquidityTrackerError),
    /// Storage error.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// An error occurred during ABI encoding/decoding.
    #[error(transparent)]
    AbiError(#[from] alloy::sol_types::Error),
}

impl From<Arc<dyn TransactionFailureReason>> for InteropBundleError {
    fn from(err: Arc<dyn TransactionFailureReason>) -> Self {
        Self::TransactionError(err)
    }
}

#[derive(Debug)]
pub enum InteropServiceMessage {
    /// Send an [`InteropBundle`].
    SendBundle(InteropBundle),
}

/// Handle to communicate with the [`InteropService`].
#[derive(Debug, Clone)]
pub struct InteropServiceHandle {
    command_tx: mpsc::UnboundedSender<InteropServiceMessage>,
}

impl InteropServiceHandle {
    /// Sends an interop bundle to the service.
    pub fn send_bundle(
        &self,
        bundle: InteropBundle,
    ) -> Result<(), mpsc::error::SendError<InteropServiceMessage>> {
        self.command_tx.send(InteropServiceMessage::SendBundle(bundle))
    }
}

/// Internal state of the interop service.
#[derive(Debug)]
struct InteropServiceInner {
    tx_service_handles: HashMap<ChainId, TransactionServiceHandle>,
    liquidity_tracker: LiquidityTracker,
}

impl InteropServiceInner {
    /// Creates a new interop service inner state.
    fn new(
        tx_service_handles: HashMap<ChainId, TransactionServiceHandle>,
        liquidity_tracker: LiquidityTracker,
    ) -> Self {
        Self { tx_service_handles, liquidity_tracker }
    }

    async fn send_and_watch_transactions(
        &self,
        transactions: &[RelayTransaction],
    ) -> Result<Vec<TransactionReceipt>, InteropBundleError> {
        let mut handles = Vec::new();

        for tx in transactions {
            let handle = self
                .tx_service_handles
                .get(&tx.chain_id())
                .ok_or_else(|| {
                    let err =
                        Arc::new(format!("no transaction service for chain {}", tx.chain_id()));
                    InteropBundleError::TransactionError(err)
                })?
                .send_transaction(tx.clone())
                .await?;
            handles.push(handle);
        }

        // Wait for all transactions to confirm or fail
        let results = handles
            .into_iter()
            .map(|mut handle| async move {
                while let Some(status) = handle.recv().await {
                    match status {
                        TransactionStatus::Confirmed(receipt) => return Ok(*receipt),
                        TransactionStatus::Failed(err) => return Err(err),
                        _ => continue,
                    }
                }

                Err(Arc::new("transaction stream ended".to_string()))
            })
            .collect::<JoinAll<_>>()
            .await;

        // Collect results and return first error if any
        Ok(results.into_iter().collect::<Result<Vec<_>, _>>()?)
    }

    #[instrument(skip(self, bundle), fields(bundle_id = %bundle.id))]
    async fn send_and_watch_bundle(&self, bundle: InteropBundle) -> Result<(), InteropBundleError> {
        let asset_transfers = bundle
            .dst_transactions
            .iter()
            .map(|tx| {
                tx.quote.output.fund_transfers().map(|transfers| {
                    transfers.into_iter().map(|(asset, amount)| (tx.quote.chain_id, asset, amount))
                })
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        self.liquidity_tracker.try_lock_liquidity(asset_transfers.clone()).await?;

        let src_receipts = self.send_and_watch_transactions(&bundle.src_transactions).await?;

        for receipt in src_receipts {
            let event = IntentExecuted::try_from_receipt(&receipt);
            if event.as_ref().is_none_or(|e| e.has_error()) {
                let reason = event
                    .as_ref()
                    .map(|e| e.err.to_string())
                    .unwrap_or_else(|| "IntentExecuted event not found".to_string());
                return Err(InteropBundleError::TransactionError(Arc::new(format!(
                    "source intent failed: {reason}",
                ))));
            }
        }

        let dst_receipts = self.send_and_watch_transactions(&bundle.dst_transactions).await?;

        for ((chain_id, asset, amount), receipt) in asset_transfers.into_iter().zip(dst_receipts) {
            self.liquidity_tracker
                .unlock_liquidity(chain_id, asset, amount, receipt.block_number.unwrap_or_default())
                .await;
        }

        Ok(())
    }
}

/// Service for handling cross-chain interop bundles.
#[derive(Debug)]
pub struct InteropService {
    inner: Arc<InteropServiceInner>,
    command_rx: mpsc::UnboundedReceiver<InteropServiceMessage>,
}

impl InteropService {
    /// Creates a new interop service.
    pub async fn new(
        providers: HashMap<ChainId, DynProvider>,
        tx_service_handles: HashMap<ChainId, TransactionServiceHandle>,
        funder_address: Address,
    ) -> eyre::Result<(Self, InteropServiceHandle)> {
        let (command_tx, command_rx) = mpsc::unbounded_channel();

        let liquidity_tracker = LiquidityTracker::new(providers, funder_address);

        let service = Self {
            inner: Arc::new(InteropServiceInner::new(tx_service_handles, liquidity_tracker)),
            command_rx,
        };

        let handle = InteropServiceHandle { command_tx };

        Ok((service, handle))
    }
}

impl Future for InteropService {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        while let Poll::Ready(Some(command)) = self.command_rx.poll_recv(cx) {
            match command {
                InteropServiceMessage::SendBundle(bundle) => {
                    let inner = Arc::clone(&self.inner);
                    tokio::spawn(async move {
                        if let Err(e) = inner.send_and_watch_bundle(bundle).await {
                            error!("Failed to process interop bundle: {:?}", e);
                        }
                    });
                }
            }
        }

        Poll::Pending
    }
}
