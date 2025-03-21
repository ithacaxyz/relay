//! Relay error types.
use alloy::{
    primitives::{Bytes, ChainId},
    transports::TransportErrorKind,
};
use core::fmt;
use jsonrpsee::core::RpcResult;
use thiserror::Error;

mod auth;
pub use auth::AuthError;

mod keys;
pub use keys::KeysError;

mod op;
pub use op::UserOpError;

mod quote;
pub use quote::QuoteError;

mod storage;
pub use storage::StorageError;

/// The overarching error type returned by `relay_estimateFee`.
#[derive(Debug, Error)]
pub enum RelayError {
    /// Errors related to 7702 authorizations.
    #[error(transparent)]
    Auth(#[from] AuthError),
    /// Errors related to quotes.
    #[error(transparent)]
    Quote(#[from] QuoteError),
    /// Errors related to user ops.
    #[error(transparent)]
    UserOp(#[from] UserOpError),
    /// Errors related to authorization keys.
    #[error(transparent)]
    Keys(#[from] KeysError),
    /// Errors related to storage.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// The chain is not supported.
    #[error("unsupported chain {0}")]
    UnsupportedChain(ChainId),
    /// An error occurred during ABI encoding/decoding.
    #[error(transparent)]
    AbiError(#[from] alloy::sol_types::Error),
    /// An error occurred talking to RPC.
    #[error(transparent)]
    RpcError(#[from] alloy::transports::RpcError<TransportErrorKind>),
    /// An internal error occurred.
    #[error(transparent)]
    InternalError(#[from] eyre::Error),
}

impl From<RelayError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(err: RelayError) -> Self {
        match err {
            RelayError::Auth(inner) => inner.into(),
            RelayError::Quote(inner) => inner.into(),
            RelayError::UserOp(inner) => inner.into(),
            RelayError::Keys(inner) => inner.into(),
            RelayError::Storage(inner) => inner.into(),
            RelayError::UnsupportedChain(_)
            | RelayError::AbiError(_)
            | RelayError::RpcError(_)
            | RelayError::InternalError(_) => internal_rpc(err),
        }
    }
}

/// A helper trait to provide an RPC error code.
pub trait ToRpcResult<Ok, Err>: Sized {
    /// Converts result to [`RpcResult`] by converting error variant to
    /// [`jsonrpsee_types::error::ErrorObject`]
    fn to_rpc_result(self) -> RpcResult<Ok>
    where
        Err: fmt::Display;
}

macro_rules! impl_error_helpers {
    ($err:ty) => {
        impl<Ok> ToRpcResult<Ok, $err> for Result<Ok, $err> {
            fn to_rpc_result(self) -> RpcResult<Ok> {
                self.map_err(|err| err.into())
            }
        }

        impl From<$err> for String {
            fn from(err: $err) -> Self {
                err.to_string()
            }
        }
    };
}

impl_error_helpers!(RelayError);
impl_error_helpers!(AuthError);
impl_error_helpers!(QuoteError);
impl_error_helpers!(UserOpError);
impl_error_helpers!(KeysError);
impl_error_helpers!(StorageError);

/// Constructs an invalid params JSON‑RPC error.
fn invalid_params(msg: impl Into<String>) -> jsonrpsee::types::error::ErrorObject<'static> {
    rpc_err(jsonrpsee::types::error::INVALID_PARAMS_CODE, msg, None)
}

/// Constructs an internal JSON‑RPC error.
fn internal_rpc(msg: impl Into<String>) -> jsonrpsee::types::error::ErrorObject<'static> {
    rpc_err(jsonrpsee::types::error::INTERNAL_ERROR_CODE, msg, None)
}

/// Constructs a JSON‑RPC error with `code`, `message` and optional `data`.
fn rpc_err(
    code: i32,
    msg: impl Into<String>,
    data: Option<Bytes>,
) -> jsonrpsee::types::error::ErrorObject<'static> {
    jsonrpsee::types::error::ErrorObject::owned(code, msg.into(), data)
}
