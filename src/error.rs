use alloy::primitives::Address;

/// Errors returned by `relay_estimateFee`
#[derive(Debug, thiserror::Error)]
pub enum EstimateFeeError {
    /// The provided fee token is not supported.
    #[error("fee token not supported: {0}")]
    UnsupportedFeeToken(Address),
    /// An error occurred talking to RPC.
    #[error(transparent)]
    RpcError(#[from] alloy::transports::RpcError<alloy::transports::TransportErrorKind>),
    /// An internal error occurred.
    #[error(transparent)]
    InternalError(#[from] eyre::Error),
}

impl From<EstimateFeeError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(error: EstimateFeeError) -> Self {
        jsonrpsee::types::error::ErrorObject::owned::<()>(
            match error {
                EstimateFeeError::InternalError(_) | EstimateFeeError::RpcError(_) => {
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
    /// The provided EIP-7702 auth item is not chain agnostic.
    #[error("the auth item is not chain agnostic")]
    AuthItemNotChainAgnostic,
    /// The `eoa` field of the provided `UserOp` is not an EIP-7702 delegated account.
    #[error("eoa not delegated: {0}")]
    EoaNotDelegated(Address),
    /// The quote expired.
    #[error("quote expired")]
    QuoteExpired,
    /// The provided quote was not signed by the relay.
    #[error("invalid quote signer")]
    InvalidQuoteSignature,
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
