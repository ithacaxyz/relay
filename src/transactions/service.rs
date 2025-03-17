use super::{
    SignerHandle,
    signer::Signer,
    transaction::{RelayTransaction, TransactionStatus},
};
use alloy::primitives::B256;
use std::{
    collections::HashMap,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::sync::{mpsc, oneshot};

/// Messages accepted by the [`TransactionService`].
#[derive(Debug)]
pub enum TransactionServiceMessage {
    /// Message to send a transaction.
    SendTransaction(Box<RelayTransaction>),
    /// Message to get the status of a given transaction.
    GetStatus(B256, oneshot::Sender<Option<TransactionStatus>>),
}

/// Handle to communicate with the [`TransactionService`].
#[derive(Debug, Clone)]
pub struct TransactionServiceHandle {
    command_tx: mpsc::UnboundedSender<TransactionServiceMessage>,
}

impl TransactionServiceHandle {
    /// Sends a transaction.
    pub fn send_transaction(&self, tx: RelayTransaction) {
        let _ = self.command_tx.send(TransactionServiceMessage::SendTransaction(Box::new(tx)));
    }

    /// Fetches the status of a transaction.
    pub fn get_status(&self, id: B256) -> oneshot::Receiver<Option<TransactionStatus>> {
        let (tx, rx) = oneshot::channel();
        let _ = self.command_tx.send(TransactionServiceMessage::GetStatus(id, tx));
        rx
    }
}

/// Service handing transactions.
#[derive(Debug)]
pub struct TransactionService {
    /// Handle to a signer responsible for broadcasting transactions.
    signer: SignerHandle,

    /// Incoming messages for the service.
    command_rx: mpsc::UnboundedReceiver<TransactionServiceMessage>,

    /// Pending transactions that are being handled by signer.
    pending_transactions: HashMap<B256, mpsc::UnboundedReceiver<TransactionStatus>>,

    /// [`RelayTransaction::id`] -> [`TransactionStatus`] mapping.
    statuses: HashMap<B256, TransactionStatus>,
}

impl TransactionService {
    /// Creates a new [`TransactionService`].
    pub fn new(signer: SignerHandle) -> (Self, TransactionServiceHandle) {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let this = Self {
            signer,
            command_rx,
            pending_transactions: Default::default(),
            statuses: HashMap::new(),
        };

        (this, TransactionServiceHandle { command_tx })
    }

    /// Creates a new [`TransactionService`] and spawns it.
    pub fn spawn(signer: Signer) -> TransactionServiceHandle {
        let (this, handle) = Self::new(signer.spawn());
        tokio::spawn(this);
        handle
    }

    fn send_transaction(&mut self, tx: RelayTransaction) {
        self.statuses.insert(tx.id, TransactionStatus::InFlight);
        self.pending_transactions.insert(tx.id, self.signer.send_transaction(tx));
    }
}

impl Future for TransactionService {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        while let Poll::Ready(Some(action)) = this.command_rx.poll_recv(cx) {
            match action {
                TransactionServiceMessage::SendTransaction(tx) => {
                    this.send_transaction(*tx);
                }
                TransactionServiceMessage::GetStatus(id, tx) => {
                    let _ = tx.send(this.statuses.get(&id).copied());
                }
            }
        }

        this.pending_transactions.retain(|id, rx| {
            while let Poll::Ready(status_opt) = rx.poll_recv(cx) {
                if let Some(status) = status_opt {
                    this.statuses.insert(*id, status);
                } else {
                    return false;
                }
            }

            true
        });

        Poll::Pending
    }
}
