use crate::types::rpc::BundleId;

use super::{
    SignerEvent, SignerHandle,
    transaction::{RelayTransaction, TransactionStatus},
};
use std::{
    collections::HashMap,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::sync::mpsc;

/// Messages accepted by the [`TransactionService`].
#[derive(Debug)]
pub enum TransactionServiceMessage {
    /// Message to send a transaction.
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

/// Service handing transactions.
#[derive(Debug)]
pub struct TransactionService {
    /// Handle to a signer responsible for broadcasting transactions.
    signer: SignerHandle,

    /// Incoming messages for the service.
    command_rx: mpsc::UnboundedReceiver<TransactionServiceMessage>,

    /// Subscriptions to transaction status updates.
    subscriptions: HashMap<BundleId, mpsc::UnboundedSender<TransactionStatus>>,
}

impl TransactionService {
    /// Creates a new [`TransactionService`].
    pub fn new(signer: SignerHandle) -> (Self, TransactionServiceHandle) {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let this = Self { signer, command_rx, subscriptions: Default::default() };

        (this, TransactionServiceHandle { command_tx })
    }

    /// Creates a new [`TransactionService`] and spawns it.
    pub fn spawn(signer: SignerHandle) -> TransactionServiceHandle {
        let (this, handle) = Self::new(signer);
        tokio::spawn(this);
        handle
    }

    fn send_transaction(&mut self, tx: RelayTransaction) {
        self.signer.send_transaction(tx);
    }
}

impl Future for TransactionService {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        while let Poll::Ready(Some(action)) = this.command_rx.poll_recv(cx) {
            match action {
                TransactionServiceMessage::SendTransaction(tx, status_tx) => {
                    this.subscriptions.insert(tx.id, status_tx);
                    this.send_transaction(tx);
                }
            }
        }

        while let Poll::Ready(Some(event)) = this.signer.poll_recv(cx) {
            match event {
                SignerEvent::TransactionStatus(id, status) => {
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
