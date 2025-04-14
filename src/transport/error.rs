//! Additional helpers for RPC error handling

use alloy::transports::TransportError;

/// An Extension trait fo [`TransportError`]
pub trait TransportErrExt {
    /// Returns true if this is a "already know" error thrown when a transaction if the transactions
    /// is already contained within the pool.
    ///
    /// This represents duplicate transaction submission.
    fn is_already_known(&self) -> bool;
}

impl TransportErrExt for TransportError {
    fn is_already_known(&self) -> bool {
        // see also: op-geth: https://github.com/ethereum-optimism/op-geth/blob/e666543dc5500428ee7c940e54263fe4968c5efd/core/txpool/legacypool/legacypool.go#L991-L993
        // reth: https://github.com/paradigmxyz/reth/blob/a3b749676c6c748bf977983c189f9f4c4f9e9fbe/crates/rpc/rpc-eth-types/src/error/mod.rs#L663-L665
        self.as_error_resp()
            .map(|err| err.message == "already known")
            .unwrap_or_default()
    }
}
