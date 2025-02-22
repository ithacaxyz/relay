use alloy::{
    primitives::{Address, B256},
    rpc::types::{TransactionReceipt, TransactionRequest},
};

use crate::types::BatchHash;

/// Transaction events emitted by the backend.
pub enum TxEvent {
    /// A transaction was queued for execution.
    Queued {
        /// The hash of the batch contained within the transaction.
        batch_hash: BatchHash,
    },
    /// A transaction was stuck in the mempool.
    Stuck {
        /// The sender of the transaction.
        from: Address,
        /// The nonce of the transaction.
        nonce: u64,
        /// The hash of the batch contained within the transaction.
        batch_hash: BatchHash,
        /// The hash of the transaction.
        transaction_hash: B256,
    },
    /// A transaction was signed and sent to the network.
    Pending {
        /// The sender of the transaction.
        from: Address,
        /// The nonce of the transaction.
        nonce: u64,
        /// The hash of the batch contained within the transaction.
        batch_hash: BatchHash,
        /// The hash of the transaction.
        transaction_hash: B256,
    },
    /// A transaction was included in a block.
    Included {
        /// The sender of the transaction.
        from: Address,
        /// The nonce of the transaction.
        nonce: u64,
        /// The hash of the batch contained within the transaction.
        batch_hash: BatchHash,
        /// The hash of the transaction.
        transaction_hash: B256,
        /// The receipt of the transaction.
        receipt: TransactionReceipt,
    },
}

pub enum BackendCommand {
    /// Submit a transaction to the backend.
    Submit {
        /// The transaction request.
        tx: TransactionRequest,
    },
}
