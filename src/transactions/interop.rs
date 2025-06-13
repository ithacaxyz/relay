use super::{
    RelayTransaction, TransactionServiceHandle, TransactionServiceMessage, TransactionStatus, TxId,
};
use crate::{
    config::TransactionServiceConfig,
    error::StorageError,
    signers::DynSigner,
    storage::{RelayStorage, StorageApi},
};
use alloy::{
    primitives::B256,
    providers::DynProvider,
};
use futures_util::StreamExt;
use std::{
    collections::HashMap,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{sync::mpsc, time};
use tracing::{debug, error, info};

/// Message accepted by the [`InteropTransactionService`].
#[derive(Debug)]
pub enum InteropTransactionServiceMessage {
    /// Execute an interop bundle of transactions.
    ExecuteBundle(InteropBundle, mpsc::UnboundedSender<InteropBundleStatus>),
}

/// Handle to communicate with the [`InteropTransactionService`].
#[derive(Debug, Clone)]
pub struct InteropTransactionServiceHandle {
    command_tx: mpsc::UnboundedSender<InteropTransactionServiceMessage>,
}

impl InteropTransactionServiceHandle {
    /// Sends an interop bundle for execution.
    pub async fn execute_bundle(
        &self,
        bundle: InteropBundle,
    ) -> mpsc::UnboundedReceiver<InteropBundleStatus> {
        let (status_tx, status_rx) = mpsc::unbounded_channel();
        let _ = self
            .command_tx
            .send(InteropTransactionServiceMessage::ExecuteBundle(bundle, status_tx));
        status_rx
    }
}

/// Status of an interop bundle execution.
#[derive(Clone, Debug)]
pub enum InteropBundleStatus {
    /// Source chain transactions are being processed.
    ProcessingSrcChain {
        pending: usize,
        confirmed: usize,
        failed: usize,
    },
    /// Destination chain transactions are being processed.
    ProcessingDstChain {
        pending: usize,
        confirmed: usize,
        failed: usize,
    },
    /// Bundle execution completed successfully.
    Completed {
        src_tx_hashes: Vec<B256>,
        dst_tx_hashes: Vec<B256>,
    },
    /// Bundle execution failed.
    Failed(Arc<dyn TransactionFailureReason>),
}

use super::transaction::TransactionFailureReason;

impl InteropBundleStatus {
    /// Whether the status is final.
    pub fn is_final(&self) -> bool {
        matches!(self, Self::Completed { .. } | Self::Failed(_))
    }
}

/// Bundle of transactions for cross-chain execution.
#[derive(Debug, Clone)]
pub struct InteropBundle {
    /// Unique identifier for the bundle.
    pub id: B256,
    /// Source chain transactions.
    pub src_transactions: Vec<RelayTransaction>,
    /// Destination chain transactions. Those can't be sent until all source chain transactions
    /// are confirmed.
    pub dst_transactions: Vec<RelayTransaction>,
}

impl InteropBundle {
    /// Creates a new interop bundle.
    pub fn new(
        src_transactions: Vec<RelayTransaction>,
        dst_transactions: Vec<RelayTransaction>,
    ) -> Self {
        Self {
            id: B256::random(),
            src_transactions,
            dst_transactions,
        }
    }
}

/// Bundle tracking state.
#[derive(Debug)]
struct BundleState {
    bundle: InteropBundle,
    status_tx: mpsc::UnboundedSender<InteropBundleStatus>,
    src_status: HashMap<TxId, TransactionStatus>,
    dst_status: HashMap<TxId, TransactionStatus>,
    src_receivers: HashMap<TxId, mpsc::UnboundedReceiver<TransactionStatus>>,
    dst_receivers: HashMap<TxId, mpsc::UnboundedReceiver<TransactionStatus>>,
}

impl BundleState {
    fn new(
        bundle: InteropBundle,
        status_tx: mpsc::UnboundedSender<InteropBundleStatus>,
    ) -> Self {
        Self {
            bundle,
            status_tx,
            src_status: HashMap::new(),
            dst_status: HashMap::new(),
            src_receivers: HashMap::new(),
            dst_receivers: HashMap::new(),
        }
    }

    /// Updates source chain transaction status.
    fn update_src_status(&mut self, tx_id: TxId, status: TransactionStatus) {
        self.src_status.insert(tx_id, status);
        self.send_status_update();
    }

    /// Updates destination chain transaction status.
    fn update_dst_status(&mut self, tx_id: TxId, status: TransactionStatus) {
        self.dst_status.insert(tx_id, status);
        self.send_status_update();
    }

    /// Checks if all source transactions are confirmed.
    fn all_src_confirmed(&self) -> bool {
        self.bundle.src_transactions.len() == self.src_status.len()
            && self
                .src_status
                .values()
                .all(|s| matches!(s, TransactionStatus::Confirmed(_)))
    }

    /// Checks if any transaction has failed.
    fn has_failed(&self) -> Option<&Arc<dyn TransactionFailureReason>> {
        self.src_status
            .values()
            .chain(self.dst_status.values())
            .find_map(|s| match s {
                TransactionStatus::Failed(err) => Some(err),
                _ => None,
            })
    }

    /// Sends current status update.
    fn send_status_update(&self) {
        let status = if self.has_failed().is_some() {
            InteropBundleStatus::Failed(self.has_failed().unwrap().clone())
        } else if self.all_dst_confirmed() {
            let src_hashes = self
                .src_status
                .values()
                .filter_map(|s| s.tx_hash())
                .collect();
            let dst_hashes = self
                .dst_status
                .values()
                .filter_map(|s| s.tx_hash())
                .collect();
            InteropBundleStatus::Completed {
                src_tx_hashes: src_hashes,
                dst_tx_hashes: dst_hashes,
            }
        } else if self.all_src_confirmed() || !self.dst_status.is_empty() {
            let (pending, confirmed, failed) = self.count_status(&self.dst_status);
            InteropBundleStatus::ProcessingDstChain {
                pending,
                confirmed,
                failed,
            }
        } else {
            let (pending, confirmed, failed) = self.count_status(&self.src_status);
            InteropBundleStatus::ProcessingSrcChain {
                pending,
                confirmed,
                failed,
            }
        };

        let _ = self.status_tx.send(status);
    }

    /// Counts transaction statuses.
    fn count_status(
        &self,
        status_map: &HashMap<TxId, TransactionStatus>,
    ) -> (usize, usize, usize) {
        let mut pending = 0;
        let mut confirmed = 0;
        let mut failed = 0;

        for status in status_map.values() {
            match status {
                TransactionStatus::InFlight | TransactionStatus::Pending(_) => pending += 1,
                TransactionStatus::Confirmed(_) => confirmed += 1,
                TransactionStatus::Failed(_) => failed += 1,
            }
        }

        (pending, confirmed, failed)
    }

    /// Checks if all destination transactions are confirmed.
    fn all_dst_confirmed(&self) -> bool {
        self.bundle.dst_transactions.len() == self.dst_status.len()
            && self
                .dst_status
                .values()
                .all(|s| matches!(s, TransactionStatus::Confirmed(_)))
    }

    /// Whether the bundle is complete (success or failure).
    fn is_complete(&self) -> bool {
        self.has_failed().is_some() || self.all_dst_confirmed()
    }
}

/// Service that orchestrates cross-chain transaction execution.
///
/// This service manages multiple [`TransactionService`] instances for different chains
/// and coordinates the execution of interop bundles.
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct InteropTransactionService {
    /// Map from chain ID to transaction service handle.
    chain_services: HashMap<u64, TransactionServiceHandle>,
    /// Active bundle states.
    active_bundles: HashMap<B256, BundleState>,
    /// Incoming messages for the service.
    command_rx: mpsc::UnboundedReceiver<InteropTransactionServiceMessage>,
    /// Storage handle.
    storage: RelayStorage,
}

impl InteropTransactionService {
    /// Creates a new [`InteropTransactionService`].
    ///
    /// Takes a map of chain IDs to their corresponding transaction service handles.
    pub fn new(
        chain_services: HashMap<u64, TransactionServiceHandle>,
        storage: RelayStorage,
    ) -> (Self, InteropTransactionServiceHandle) {
        let (command_tx, command_rx) = mpsc::unbounded_channel();

        let service = Self {
            chain_services,
            active_bundles: HashMap::new(),
            command_rx,
            storage,
        };

        let handle = InteropTransactionServiceHandle { command_tx };

        (service, handle)
    }

    /// Processes a new interop bundle.
    async fn process_bundle(
        &mut self,
        bundle: InteropBundle,
        status_tx: mpsc::UnboundedSender<InteropBundleStatus>,
    ) {
        info!(bundle_id = %bundle.id, "Processing new interop bundle");

        let mut state = BundleState::new(bundle.clone(), status_tx);

        // Submit all source chain transactions
        for tx in &bundle.src_transactions {
            let chain_id = tx.chain_id();
            if let Some(service) = self.chain_services.get(&chain_id) {
                match service.send_transaction(tx.clone()).await {
                    Ok(rx) => {
                        state.src_receivers.insert(tx.id, rx);
                        debug!(tx_id = %tx.id, chain_id, "Submitted source transaction");
                    }
                    Err(e) => {
                        error!(tx_id = %tx.id, chain_id, error = %e, "Failed to submit source transaction");
                        state.update_src_status(tx.id, TransactionStatus::Failed(Arc::new(e)));
                    }
                }
            } else {
                error!(chain_id, "No transaction service for chain");
                state.update_src_status(
                    tx.id,
                    TransactionStatus::Failed(Arc::new(InteropError::ChainNotSupported(chain_id))),
                );
            }
        }

        self.active_bundles.insert(bundle.id, state);
    }

    /// Polls status updates for a bundle.
    fn poll_bundle_updates(&mut self, bundle_id: &B256, cx: &mut Context<'_>) {
        let Some(state) = self.active_bundles.get_mut(bundle_id) else {
            return;
        };

        // Poll source transaction updates
        let src_ids: Vec<_> = state.src_receivers.keys().cloned().collect();
        for tx_id in src_ids {
            if let Some(mut rx) = state.src_receivers.remove(&tx_id) {
                match rx.poll_recv(cx) {
                    Poll::Ready(Some(status)) => {
                        debug!(tx_id = %tx_id, ?status, "Source transaction status update");
                        state.update_src_status(tx_id, status.clone());
                        if !status.is_final() {
                            state.src_receivers.insert(tx_id, rx);
                        }
                    }
                    Poll::Ready(None) => {
                        // Channel closed
                        debug!(tx_id = %tx_id, "Source transaction channel closed");
                    }
                    Poll::Pending => {
                        state.src_receivers.insert(tx_id, rx);
                    }
                }
            }
        }

        // Poll destination transaction updates
        let dst_ids: Vec<_> = state.dst_receivers.keys().cloned().collect();
        for tx_id in dst_ids {
            if let Some(mut rx) = state.dst_receivers.remove(&tx_id) {
                match rx.poll_recv(cx) {
                    Poll::Ready(Some(status)) => {
                        debug!(tx_id = %tx_id, ?status, "Destination transaction status update");
                        state.update_dst_status(tx_id, status.clone());
                        if !status.is_final() {
                            state.dst_receivers.insert(tx_id, rx);
                        }
                    }
                    Poll::Ready(None) => {
                        // Channel closed
                        debug!(tx_id = %tx_id, "Destination transaction channel closed");
                    }
                    Poll::Pending => {
                        state.dst_receivers.insert(tx_id, rx);
                    }
                }
            }
        }

        // Check if we should submit destination transactions
        if state.all_src_confirmed() && state.dst_receivers.is_empty() {
            let bundle = state.bundle.clone();
            let storage = self.storage.clone();
            let chain_services = self.chain_services.clone();

            // Submit destination transactions
            for tx in &bundle.dst_transactions {
                let chain_id = tx.chain_id();
                if let Some(service) = chain_services.get(&chain_id) {
                    let tx_clone = tx.clone();
                    let service_clone = service.clone();
                    
                    // We need to handle this synchronously in the poll
                    match futures_util::executor::block_on(service_clone.send_transaction(tx_clone)) {
                        Ok(rx) => {
                            state.dst_receivers.insert(tx.id, rx);
                            debug!(tx_id = %tx.id, chain_id, "Submitted destination transaction");
                        }
                        Err(e) => {
                            error!(tx_id = %tx.id, chain_id, error = %e, "Failed to submit destination transaction");
                            state.update_dst_status(tx.id, TransactionStatus::Failed(Arc::new(e)));
                        }
                    }
                } else {
                    error!(chain_id, "No transaction service for chain");
                    state.update_dst_status(
                        tx.id,
                        TransactionStatus::Failed(Arc::new(InteropError::ChainNotSupported(
                            chain_id,
                        ))),
                    );
                }
            }
        }
    }
}

impl futures_util::Future for InteropTransactionService {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        // Process incoming commands
        while let Poll::Ready(msg_opt) = this.command_rx.poll_recv(cx) {
            match msg_opt {
                Some(InteropTransactionServiceMessage::ExecuteBundle(bundle, status_tx)) => {
                    let bundle_id = bundle.id;
                    futures_util::executor::block_on(this.process_bundle(bundle, status_tx));
                }
                None => {
                    // Command channel closed
                    debug!("Interop service command channel closed");
                    return Poll::Ready(());
                }
            }
        }

        // Poll all active bundles
        let bundle_ids: Vec<_> = this.active_bundles.keys().cloned().collect();
        for bundle_id in bundle_ids {
            this.poll_bundle_updates(&bundle_id, cx);
        }

        // Clean up completed bundles
        this.active_bundles.retain(|id, state| {
            if state.is_complete() {
                info!(bundle_id = %id, "Bundle execution completed");
                false
            } else {
                true
            }
        });

        Poll::Pending
    }
}

/// Errors specific to interop operations.
#[derive(Debug, thiserror::Error)]
pub enum InteropError {
    /// Chain is not supported.
    #[error("Chain {0} is not supported")]
    ChainNotSupported(u64),
}

impl TransactionFailureReason for InteropError {}
