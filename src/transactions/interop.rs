use super::{
    RelayTransaction, TransactionFailureReason, TransactionServiceHandle, TransactionStatus,
};
use crate::{error::StorageError, types::rpc::BundleId};
use alloy::primitives::{ChainId, map::HashMap};
use futures_util::future::JoinAll;
use std::sync::Arc;
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
    /// Storage error.
    #[error(transparent)]
    Storage(#[from] StorageError),
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
}

impl InteropServiceInner {
    /// Creates a new interop service inner state.
    fn new(tx_service_handles: HashMap<ChainId, TransactionServiceHandle>) -> Self {
        Self { tx_service_handles }
    }

    async fn send_and_watch_transactions(
        &self,
        transactions: &[RelayTransaction],
    ) -> Result<(), InteropBundleError> {
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
                        TransactionStatus::Confirmed(_) => return Ok(()),
                        TransactionStatus::Failed(err) => return Err(err),
                        _ => continue,
                    }
                }

                Err(Arc::new("transaction stream ended".to_string()))
            })
            .collect::<JoinAll<_>>()
            .await;

        // Collect results and return first error if any
        results.into_iter().collect::<Result<Vec<_>, _>>()?;

        Ok(())
    }

    #[instrument(skip(self, bundle), fields(bundle_id = %bundle.id))]
    async fn send_and_watch_bundle(&self, bundle: InteropBundle) -> Result<(), InteropBundleError> {
        self.send_and_watch_transactions(&bundle.src_transactions).await?;
        self.send_and_watch_transactions(&bundle.dst_transactions).await?;

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
    pub fn new(
        tx_service_handles: HashMap<ChainId, TransactionServiceHandle>,
    ) -> (Self, InteropServiceHandle) {
        let (command_tx, command_rx) = mpsc::unbounded_channel();

        let service =
            Self { inner: Arc::new(InteropServiceInner::new(tx_service_handles)), command_rx };

        let handle = InteropServiceHandle { command_tx };

        (service, handle)
    }

    /// Runs the interop service.
    pub async fn into_future(mut self) {
        loop {
            tokio::select! {
                Some(command) = self.command_rx.recv() => {
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
                else => break,
            }
        }
    }
}
