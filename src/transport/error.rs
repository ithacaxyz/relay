//! Additional helpers for RPC error handling

use alloy::transports::TransportError;

/// An Extension trait fo [`TransportError`]
pub trait TransportErrExt {
    /// Returns true if this is a "already know" error thrown when a transaction if the transactions
    /// is already contained within the pool.
    ///
    /// This represents duplicate transaction submission.
    fn is_already_known(&self) -> bool;

    /// Returns true if this is a "replacement transaction underpriced" error thrown when we submit
    /// a transaction with a nonce that already exists in the pool.
    fn is_replacement_underpriced(&self) -> bool;

    /// Returns true if this is a "transaction underpriced" error thrown when we submit a
    /// transaction that has a gas price too low to be included.
    fn is_transaction_underpriced(&self) -> bool;

    /// Returns true if this is a "nonce tool" error thrown when we submit a transaction with a
    /// higher nonce that what is on chain
    fn is_nonce_too_low(&self) -> bool;
}

impl TransportErrExt for TransportError {
    fn is_already_known(&self) -> bool {
        // see also: op-geth: https://github.com/ethereum-optimism/op-geth/blob/e666543dc5500428ee7c940e54263fe4968c5efd/core/txpool/legacypool/legacypool.go#L991-L993
        // reth: https://github.com/paradigmxyz/reth/blob/a3b749676c6c748bf977983c189f9f4c4f9e9fbe/crates/rpc/rpc-eth-types/src/error/mod.rs#L663-L665
        self.as_error_resp().map(|err| err.message == "already known").unwrap_or_default()
    }

    fn is_replacement_underpriced(&self) -> bool {
        // see also: geth: https://github.com/ethereum/go-ethereum/blob/a56558d0920b74b6553185de4aff79c3de534e01/core/txpool/errors.go#L38-L38
        self.as_error_resp()
            .map(|err| err.message.contains("replacement transaction underpriced"))
            .unwrap_or_default()
    }

    fn is_transaction_underpriced(&self) -> bool {
        // see also: geth: https://github.com/ethereum/go-ethereum/blob/a56558d0920b74b6553185de4aff79c3de534e01/core/txpool/errors.go#L34-L34
        self.as_error_resp()
            .map(|err| err.message.contains("transaction underpriced"))
            .unwrap_or_default()
    }

    fn is_nonce_too_low(&self) -> bool {
        // see also: geth: https://github.com/ethereum/go-ethereum/blob/85077be58edea572f29c3b1a6a055077f1a56a8b/core/error.go#L45-L47
        self.as_error_resp().map(|err| err.message.contains("nonce too low")).unwrap_or_default()
    }
}
