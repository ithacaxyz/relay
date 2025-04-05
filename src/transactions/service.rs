use crate::{signers::DynSigner, storage::RelayStorage};

use super::{
    Signer, SignerEvent, SignerHandle, SignerId, TxId,
    metrics::TransactionServiceMetrics,
    transaction::{RelayTransaction, TransactionStatus},
};
use alloy::providers::{DynProvider, Provider};
use rand::seq::IndexedRandom;
use std::{
    collections::HashMap,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::sync::mpsc;
use tracing::debug;

/// Messages accepted by the [`TransactionService`].
#[derive(Debug)]
pub enum TransactionServiceMessage {
    /// Message to send a transaction and receive events about the status of the transaction.
    SendTransaction(RelayTransaction, mpsc::UnboundedSender<TransactionStatus>),
}

/// Handle to communicate with the [`TransactionService`].
#[derive(Debug, Clone)]
pub struct TransactionServiceHandle {
    command_tx: mpsc::UnboundedSender<TransactionServiceMessage>,
}

impl TransactionServiceHandle {
    /// Sends a transaction.
    pub fn send_transaction(
        &self,
        tx: RelayTransaction,
    ) -> mpsc::UnboundedReceiver<TransactionStatus> {
        let (status_tx, status_rx) = mpsc::unbounded_channel();
        let _ = self.command_tx.send(TransactionServiceMessage::SendTransaction(tx, status_tx));
        status_rx
    }
}

/// Service that handles transactions by dispatching outgoing transaction to an available signer and
/// monitors the state of the transaction.
/// Receives incoming [`RelayTransaction`] requests and routes them to an available signer.
#[derive(Debug)]
pub struct TransactionService2 {
    /// Handles of _all_ available signers responsible for broadcasting transactions.
    ///
    /// This forms a bijection with {active,paused} signers, meaning each signer id is either
    /// `active` OR `paused`.
    signers: HashMap<SignerId, SignerHandle>,
    /// Signers we currently can use to dispatch _new_ requests to.
    active_signers: Vec<SignerId>,
    /// Signers that are currently paused until re-activated.
    paused_signers: Vec<SignerId>,
    /// Tracks the total number of processed [`RelayTransaction`].
    ///
    /// This is used to cheaply cycle through active signers.
    transaction_counter: usize,
    /// Message channel from signers to this service.
    from_signers: mpsc::UnboundedReceiver<SignerEvent>,
    /// Incoming messages for the service.
    command_rx: mpsc::UnboundedReceiver<TransactionServiceMessage>,
    /// Subscriptions to transaction status updates back to the initiator of the transaction.
    ///
    /// This keeps a holistic view of all active transactions.
    // TODO: should we even maintain this here or directly wire it in the signer.
    subscriptions: HashMap<TxId, mpsc::UnboundedSender<TransactionStatus>>,
    /// Metrics of the service.
    metrics: Arc<TransactionServiceMetrics>,
}

impl TransactionService2 {
    /// Moves a signer from paused to active if it is currently paused
    fn activate_signer(&mut self, signer_id: SignerId) {
        if let Some(pos) = self.paused_signers.iter().position(|id| *id == signer_id) {
            // remove signer from paused
            self.paused_signers.remove(pos);

            debug_assert!(
                self.is_paused_signer(&signer_id),
                "signer is still paused {:?}; duplicate entry",
                signer_id
            );
            debug_assert!(
                !self.is_active_signer(&signer_id),
                "signer is already active {:?}",
                signer_id
            );

            // activate signer
            self.active_signers.push(signer_id);
        }
    }

    /// Moves a signer from active to paused if it is currently active
    fn pause_signer(&mut self, signer_id: SignerId) {
        if let Some(pos) = self.active_signers.iter().position(|id| *id == signer_id) {
            // remove signer from active
            self.active_signers.remove(pos);

            debug_assert!(
                self.is_active_signer(&signer_id),
                "signer is still active {:?}; duplicate entry",
                signer_id
            );
            debug_assert!(
                !self.is_paused_signer(&signer_id),
                "signer is already paused {:?}",
                signer_id
            );

            // activate signer
            self.paused_signers.push(signer_id);
        }
    }

    /// Returns true if the given signer is currently active.
    fn is_active_signer(&self, signer_id: &SignerId) -> bool {
        self.active_signers.contains(signer_id)
    }

    /// Returns true if the given signer is currently paused.
    fn is_paused_signer(&self, signer_id: &SignerId) -> bool {
        self.paused_signers.contains(signer_id)
    }

    /// Picks the next active signer for dispatching a transaction.
    fn next_active_signer(&mut self) -> Option<&SignerHandle> {
        if self.active_signers.is_empty() {
            return None;
        }

        let idx = self.transaction_counter % self.active_signers.len();
        let id = self.active_signers.swap_remove(idx);
        self.active_signers.push(id);
        self.signers.get(&id)
    }

    /// Sends the given transaction to an available signer.
    fn send_transaction(
        &mut self,
        tx: RelayTransaction,
        status_tx: mpsc::UnboundedSender<TransactionStatus>,
    ) {
        debug_assert!(!self.active_signers.is_empty());
        debug_assert!(
            !self.subscriptions.contains_key(&tx.id),
            "tx subscription already exists {}",
            tx.id
        );

        self.subscriptions.insert(tx.id, status_tx);
        self.next_active_signer().expect("no signers").send_transaction(tx);
        self.transaction_counter += 1;
        self.metrics.sent.increment(1);
    }
}

impl Future for TransactionService2 {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        // drain all commands
        while let Poll::Ready(Some(action)) = this.command_rx.poll_recv(cx) {
            match action {
                TransactionServiceMessage::SendTransaction(tx, status_tx) => {
                    this.send_transaction(tx, status_tx);
                }
            }
        }

        // drain messages from signers
        while let Poll::Ready(Some(event)) = this.from_signers.poll_recv(cx) {
            match event {
                SignerEvent::TransactionStatus(id, status) => {
                    match &status {
                        TransactionStatus::Failed(err) => {
                            debug!(tx_id = %id, %err, "transaction failed");
                            this.metrics.failed.increment(1);
                        }
                        TransactionStatus::Confirmed(hash) => {
                            debug!(tx_id = %id, %hash, "transaction confirmed");
                            this.metrics.confirmed.increment(1);
                        }
                        _ => {}
                    }

                    if let Some(status_tx) = this.subscriptions.get(&id) {
                        let _ = status_tx.send(status.clone());
                    }

                    if status.is_final() {
                        this.subscriptions.remove(&id);
                    }
                }
            }
        }

        Poll::Pending
    }
}

/// Service that handles transactions by dispatching outgoing transaction to an available signer and
/// monitors the state of the transaction.
#[derive(Debug)]
pub struct TransactionService {
    /// Handles of signers responsible for broadcasting transactions.
    signers: Vec<SignerHandle>,

    /// Incoming messages for the service.
    command_rx: mpsc::UnboundedReceiver<TransactionServiceMessage>,

    /// Subscriptions to transaction status updates.
    subscriptions: HashMap<TxId, mpsc::UnboundedSender<TransactionStatus>>,

    /// Metrics of the service.
    metrics: Arc<TransactionServiceMetrics>,
}

impl TransactionService {
    /// Creates a new [`TransactionService`].
    pub fn new(
        signers: Vec<SignerHandle>,
        metrics: Arc<TransactionServiceMetrics>,
    ) -> (Self, TransactionServiceHandle) {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let this = Self { signers, command_rx, subscriptions: Default::default(), metrics };

        (this, TransactionServiceHandle { command_tx })
    }

    /// Creates a new [`TransactionService`] and spawns it.
    ///
    /// This also spawns dedicated [`Signer`] task for each configured signer
    pub async fn spawn(
        provider: DynProvider,
        signers: Vec<DynSigner>,
        storage: RelayStorage,
    ) -> TransactionServiceHandle {
        let metrics = Arc::new(TransactionServiceMetrics::new_with_labels(&[(
            "chain_id",
            provider.get_chain_id().await.unwrap().to_string(),
        )]));
        let signers = futures_util::future::try_join_all(signers.into_iter().map(|signer| {
            Signer::spawn(provider.clone(), signer, storage.clone(), metrics.clone())
        }))
        .await
        .expect("failed to build signers");

        let (this, handle) = Self::new(signers, metrics);
        tokio::spawn(this);
        handle
    }

    /// Sends the given transaction to a randomly chosen signer.
    fn send_transaction(
        &mut self,
        tx: RelayTransaction,
        status_tx: mpsc::UnboundedSender<TransactionStatus>,
    ) {
        self.subscriptions.insert(tx.id, status_tx);
        self.signers.choose(&mut rand::rng()).expect("no signers").send_transaction(tx);
        self.metrics.sent.increment(1);
    }
}

impl Future for TransactionService {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        while let Poll::Ready(Some(action)) = this.command_rx.poll_recv(cx) {
            match action {
                TransactionServiceMessage::SendTransaction(tx, status_tx) => {
                    this.send_transaction(tx, status_tx);
                }
            }
        }

        for signer in &mut this.signers {
            while let Poll::Ready(Some(event)) = signer.poll_recv(cx) {
                match event {
                    SignerEvent::TransactionStatus(id, status) => {
                        match &status {
                            TransactionStatus::Failed(err) => {
                                debug!(tx_id = %id, %err, "transaction failed");
                                this.metrics.failed.increment(1);
                            }
                            TransactionStatus::Confirmed(hash) => {
                                debug!(tx_id = %id, %hash, "transaction confirmed");
                                this.metrics.confirmed.increment(1);
                            }
                            _ => {}
                        }

                        if let Some(status_tx) = this.subscriptions.get(&id) {
                            let _ = status_tx.send(status.clone());
                        }

                        if status.is_final() {
                            this.subscriptions.remove(&id);
                        }
                    }
                }
            }
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dispatch_requests() {}
}
