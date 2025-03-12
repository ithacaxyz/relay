use super::{
    SendTxError,
    signer::Signer,
    transaction::{
        DroppedTransaction, PendingTransaction, RelayTransaction, SentTransaction,
        TransactionStatus,
    },
};
use alloy::primitives::B256;
use futures_util::{StreamExt, stream::FuturesUnordered};
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
    SendTransaction(RelayTransaction),
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
        let _ = self.command_tx.send(TransactionServiceMessage::SendTransaction(tx));
    }

    /// Fetches the status of a transaction.
    pub fn get_status(&self, id: B256) -> oneshot::Receiver<Option<TransactionStatus>> {
        let (tx, rx) = oneshot::channel();
        let _ = self.command_tx.send(TransactionServiceMessage::GetStatus(id, tx));
        rx
    }
}

/// Future that signs and sends a transaction. Returns [`PendingTransaction`] on success and
/// [`SendTxError`] on failure.
type InFlightTransactionFuture =
    Pin<Box<dyn Future<Output = Result<PendingTransaction, SendTxError>> + Send>>;

/// Future awaiting a pending transaction outcome. Returns [`SentTransaction`] on success and
/// [`DroppedTransaction`] on failure.
type PendingTransactionFuture =
    Pin<Box<dyn Future<Output = Result<SentTransaction, DroppedTransaction>> + Send>>;

/// Service handing transactions.
#[derive(Debug)]
pub struct TransactionService {
    /// Signer used to send transactions.
    signer: Signer,

    /// Incoming messages for the service.
    command_rx: mpsc::UnboundedReceiver<TransactionServiceMessage>,

    /// Transactions being broadcasted.
    in_flight_transactions: FuturesUnordered<InFlightTransactionFuture>,

    /// Pending transactions that has been broadcasted.
    pending_transactions: FuturesUnordered<PendingTransactionFuture>,

    /// [`RelayTransaction::id`] -> [`TransactionStatus`] mapping.
    statuses: HashMap<B256, TransactionStatus>,
}

impl TransactionService {
    /// Creates a new [`TransactionService`].
    pub fn new(signer: Signer) -> (Self, TransactionServiceHandle) {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let this = Self {
            signer,
            command_rx,
            in_flight_transactions: Default::default(),
            pending_transactions: Default::default(),
            statuses: HashMap::new(),
        };

        (this, TransactionServiceHandle { command_tx })
    }

    /// Creates a new [`TransactionService`] and spawns it.
    pub fn spawn(signer: Signer) -> TransactionServiceHandle {
        let (this, handle) = Self::new(signer);
        tokio::spawn(this);
        handle
    }

    fn send_transaction(&mut self, tx: RelayTransaction) {
        self.statuses.insert(tx.id, TransactionStatus::InFlight);

        let signer = self.signer.clone();
        self.in_flight_transactions
            .push(Box::pin(async move { signer.send_transaction(tx.clone()).await }));
    }

    fn on_sent_transaction(&mut self, tx: PendingTransaction) {
        self.statuses.insert(tx.tx.tx.id, TransactionStatus::Pending(tx.tx.tx_hash));
        self.pending_transactions.push(Box::pin(async move {
            let PendingTransaction { tx, handle } = tx;
            match handle.await {
                Ok(_) => Ok(tx),
                Err(error) => Err(DroppedTransaction { tx, error }),
            }
        }));
    }

    fn on_confirmed_transaction(&mut self, tx: SentTransaction) {
        self.statuses.insert(tx.tx.id, TransactionStatus::Confirmed(tx.tx_hash));
    }

    fn on_failed_send(&mut self, error: SendTxError) {
        let SendTxError { kind, tx, nonce } = error;
        self.statuses.insert(tx.id, TransactionStatus::Failed);
    }

    fn on_dropped_transaction(&mut self, tx: DroppedTransaction) {
        self.statuses.insert(tx.tx.tx.id, TransactionStatus::Failed);
    }
}

impl Future for TransactionService {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        while let Poll::Ready(Some(action)) = this.command_rx.poll_recv(cx) {
            match action {
                TransactionServiceMessage::SendTransaction(tx) => {
                    this.send_transaction(tx);
                }
                TransactionServiceMessage::GetStatus(id, tx) => {
                    let _ = tx.send(this.statuses.get(&id).copied());
                }
            }
        }

        while let Poll::Ready(Some(result)) = this.in_flight_transactions.poll_next_unpin(cx) {
            match result {
                Ok(tx) => this.on_sent_transaction(tx),
                Err(err) => this.on_failed_send(err),
            }
        }

        while let Poll::Ready(Some(result)) = this.pending_transactions.poll_next_unpin(cx) {
            match result {
                Ok(tx) => this.on_confirmed_transaction(tx),
                Err(dropped) => this.on_dropped_transaction(dropped),
            }
        }

        Poll::Pending
    }
}
