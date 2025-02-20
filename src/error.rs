//! Relay error types.

use alloy::{
    primitives::{Address, B256, Bytes, ChainId, U256},
    rpc::types::error::EthRpcErrorCode,
};

/// Errors returned by `relay_estimateFee`
#[derive(Debug, thiserror::Error)]
pub enum EstimateFeeError {
    /// The chain is not supported.
    #[error("unsupported chain {0}")]
    UnsupportedChain(ChainId),
    /// The provided fee token is not supported.
    #[error("fee token not supported: {0}")]
    UnsupportedFeeToken(Address),
    /// The price for fee token is not available.
    #[error("fee token price not currently available: {0}")]
    UnavailablePrice(Address),
    /// The key type is not supported.
    #[error("only supports `p256`, `webauthnp256` and `secp256k1` key types")]
    UnsupportedKeyType,
    /// The userop reverted when estimating gas.
    #[error("op reverted: {revert_reason}")]
    OpRevert {
        /// The error code returned by the entrypoint.
        revert_reason: Bytes,
    },
    /// The userop could not be simulated.
    #[error("the op could not be simulated")]
    SimulationError,
    /// An error occurred talking to RPC.
    #[error(transparent)]
    RpcError(#[from] alloy::transports::RpcError<alloy::transports::TransportErrorKind>),
    /// An internal error occurred.
    #[error(transparent)]
    InternalError(#[from] eyre::Error),
}

impl From<EstimateFeeError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(error: EstimateFeeError) -> Self {
        if let EstimateFeeError::OpRevert { ref revert_reason } = error {
            return jsonrpsee::types::error::ErrorObject::owned::<Bytes>(
                EthRpcErrorCode::ExecutionError.code(),
                error.to_string(),
                Some(revert_reason.clone()),
            );
        }

        jsonrpsee::types::error::ErrorObject::owned::<()>(
            match error {
                EstimateFeeError::InternalError(_)
                | EstimateFeeError::SimulationError
                | EstimateFeeError::RpcError(_)
                | EstimateFeeError::UnavailablePrice(_) => {
                    jsonrpsee::types::error::INTERNAL_ERROR_CODE
                }
                _ => jsonrpsee::types::error::INVALID_PARAMS_CODE,
            },
            error.to_string(),
            None,
        )
    }
}

/// Errors returned by `relay_sendAction`
#[derive(Debug, thiserror::Error)]
pub enum SendActionError {
    /// The chain is not supported.
    #[error("unsupported chain {0}")]
    UnsupportedChain(ChainId),
    /// The payment recipient in the provided [`UserOp`] is not the entrypoint or the tx signer.
    #[error("the payment recipient is not the entrypoint or the signer")]
    WrongPaymentRecipient,
    /// The provided EIP-7702 auth item is not chain agnostic.
    #[error("the auth item is not chain agnostic")]
    AuthItemNotChainAgnostic,
    /// The provided EIP-7702 auth item has an invalid nonce.
    #[error("invalid auth item nonce, expected {expected}, got {got}")]
    AuthItemInvalidNonce {
        /// The nonce expected.
        expected: u64,
        /// The nonce in the authorization item.
        got: u64,
    },
    /// The `eoa` field of the provided `UserOp` is not an EIP-7702 delegated account.
    #[error("eoa not delegated: {0}")]
    EoaNotDelegated(Address),
    /// The quote was signed for a different authorization item.
    #[error("invalid authorization item, expected {expected:?}, got {got:?}")]
    InvalidAuthItem {
        /// The expected item.
        expected: Option<Address>,
        /// The item in the request.
        got: Option<Address>,
    },
    /// The payment amount in the userop did not match the amount in the quote.
    #[error("invalid fee amount, expected {expected}, got {got}")]
    InvalidFeeAmount {
        /// The amount expected.
        expected: U256,
        /// The amount in the [`UserOp`].
        got: U256,
    },
    /// The quote was signed for a different userop.
    #[error("invalid op digest, expected {expected}, got {got}")]
    InvalidOpDigest {
        /// The digest expected.
        expected: B256,
        /// The digest of the [`UserOp`].
        got: B256,
    },
    /// The quote expired.
    #[error("quote expired")]
    QuoteExpired,
    /// The provided quote was not signed by the relay.
    #[error("invalid quote signer")]
    InvalidQuoteSignature,
    /// The userop reverted when trying transaction.
    #[error("op reverted: {revert_reason}")]
    OpRevert {
        /// The error code returned by the entrypoint.
        revert_reason: Bytes,
    },
    /// An error occurred talking to RPC.
    #[error(transparent)]
    RpcError(#[from] alloy::transports::RpcError<alloy::transports::TransportErrorKind>),
    /// An internal error occurred.
    #[error(transparent)]
    InternalError(#[from] eyre::Error),
}

impl From<SendActionError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(error: SendActionError) -> Self {
        jsonrpsee::types::error::ErrorObject::owned::<()>(
            match error {
                SendActionError::InternalError(_) | SendActionError::RpcError(_) => {
                    jsonrpsee::types::error::INTERNAL_ERROR_CODE
                }
                _ => jsonrpsee::types::error::INVALID_PARAMS_CODE,
            },
            error.to_string(),
            None,
        )
    }
}

/// Price oracle related errors
#[derive(Debug, thiserror::Error)]
pub enum PriceOracleError {
    /// An internal error occurred.
    #[error(transparent)]
    InternalError(#[from] eyre::Error),
}

/// Errors when performing `eth_call`s and decoding the result.
#[derive(Debug, thiserror::Error)]
pub enum CallError {
    /// The userop reverted when estimating gas.
    #[error("op reverted: {revert_reason}")]
    OpRevert {
        /// The error code returned by the entrypoint.
        revert_reason: Bytes,
    },
    /// An error occurred talking to RPC.
    #[error(transparent)]
    RpcError(#[from] alloy::transports::RpcError<alloy::transports::TransportErrorKind>),
    /// An error occurred ABI enc/decoding.
    #[error(transparent)]
    AbiError(#[from] alloy::sol_types::Error),
}

impl From<CallError> for EstimateFeeError {
    fn from(err: CallError) -> Self {
        match err {
            CallError::OpRevert { revert_reason } => Self::OpRevert { revert_reason },
            CallError::RpcError(err) => Self::RpcError(err),
            CallError::AbiError(err) => Self::InternalError(err.into()),
        }
    }
}
