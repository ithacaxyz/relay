//! Relay error types.

use alloy::{
    primitives::{Address, B256, Bytes, ChainId, U256},
    transports::TransportErrorKind,
};
use core::fmt;
use jsonrpsee::core::RpcResult;

use crate::storage::StorageError;

/// Errors related to 7702 authorizations.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// Invalid authorization item address.
    #[error("invalid auth item, expected {expected}, got {got}")]
    InvalidAuthAddress {
        /// The address expected.
        expected: Address,
        /// The address in the authorization item.
        got: Address,
    },
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
    /// The quote was signed for a different authorization item.
    #[error("invalid authorization item, expected {expected:?}, got {got:?}")]
    InvalidAuthItem {
        /// The expected item.
        expected: Option<Address>,
        /// The item in the request.
        got: Option<Address>,
    },
    /// The `eoa` field of the provided `UserOp` is not an EIP-7702 delegated account.
    #[error("eoa not delegated: {0}")]
    EoaNotDelegated(Address),
}

/// Errors related to quotes.
#[derive(Debug, thiserror::Error)]
pub enum QuoteError {
    /// The quote expired.
    #[error("quote expired")]
    QuoteExpired,
    /// The provided quote was not signed by the relay.
    #[error("invalid quote signer")]
    InvalidQuoteSignature,
    /// The provided fee token is not supported.
    #[error("fee token not supported: {0}")]
    UnsupportedFeeToken(Address),
    /// The price for fee token is not available.
    #[error("fee token price not currently available: {0}")]
    UnavailablePrice(Address),
    /// The payment amount in the userop did not match the amount in the quote.
    #[error("invalid fee amount, expected {expected}, got {got}")]
    InvalidFeeAmount {
        /// The amount expected.
        expected: U256,
        /// The amount in the [`UserOp`].
        got: U256,
    },
}

/// Errors related to user ops.
#[derive(Debug, thiserror::Error)]
pub enum UserOpError {
    /// The userop could not be simulated.
    #[error("the op could not be simulated")]
    SimulationError,
    /// The quote was signed for a different userop.
    #[error("invalid op digest, expected {expected}, got {got}")]
    InvalidOpDigest {
        /// The digest expected.
        expected: B256,
        /// The digest of the [`UserOp`].
        got: B256,
    },
    /// The userop reverted when trying transaction.
    #[error("op reverted: {revert_reason}")]
    OpRevert {
        /// The error code returned by the entrypoint.
        revert_reason: Bytes,
    },
}

/// Errors related to authorization keys.
#[derive(Debug, thiserror::Error)]
pub enum KeysError {
    /// The key type is not supported.
    #[error("only supports `p256`, `webauthnp256` and `secp256k1` key types")]
    UnsupportedKeyType,
    /// Missing at least one admin authorization key.
    #[error("should have at least one admin authorization key")]
    MissingAdminKey,
    /// Invalid account key registry a data.
    #[error("invalid account key registry a data for ID {0}")]
    InvalidRegistryData(Address),
}

/// The overarching error type returned by `relay_estimateFee`.
#[derive(Debug, thiserror::Error)]
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
    /// An error occurred ABI enc/decoding.
    #[error(transparent)]
    AbiError(#[from] alloy::sol_types::Error),
    /// An error occurred talking to RPC.
    #[error(transparent)]
    RpcError(#[from] alloy::transports::RpcError<alloy::transports::TransportErrorKind>),
    /// An internal error occurred.
    #[error(transparent)]
    InternalError(#[from] eyre::Error),
}

/// Helper trait to easily convert various `Result` types into [`RpcResult`]
pub trait ToRpcResult<Ok, Err>: Sized {
    /// Converts result to [`RpcResult`] by converting error variant to
    /// [`jsonrpsee::types::error::ErrorObject`]
    fn to_rpc_result(self) -> RpcResult<Ok>
    where
        Err: fmt::Display,
    {
        self.map_internal_err(|err| err.to_string())
    }

    /// Converts result to [`RpcResult`] by converting error variant to
    /// [`jsonrpsee::types::error::ErrorObject`]
    fn to_params_result(self) -> RpcResult<Ok>
    where
        Err: fmt::Display,
    {
        self.map_invalid_params_err(|err| err.to_string())
    }

    /// Converts this type into an [`RpcResult`]
    fn map_rpc_err<'a, F, M>(self, op: F) -> RpcResult<Ok>
    where
        F: FnOnce(Err) -> (i32, M, Option<&'a [u8]>),
        M: Into<String>;

    /// Converts this type into an [`RpcResult`] with the
    /// [`jsonrpsee::types::error::INTERNAL_ERROR_CODE`] and the given message.
    fn map_internal_err<F, M>(self, op: F) -> RpcResult<Ok>
    where
        F: FnOnce(Err) -> M,
        M: Into<String>;

    /// Converts this type into an [`RpcResult`] with the
    /// [`jsonrpsee::types::error::INVALID_PARAMS_CODE`] and the given message.
    fn map_invalid_params_err<F, M>(self, op: F) -> RpcResult<Ok>
    where
        F: FnOnce(Err) -> M,
        M: Into<String>;

}

/// A macro that implements the `ToRpcResult` for a specific error type
#[macro_export]
macro_rules! impl_to_rpc_result {
    ($err:ty) => {
        impl<Ok> ToRpcResult<Ok, $err> for Result<Ok, $err> {
            #[inline]
            fn map_rpc_err<'a, F, M>(self, op: F) -> jsonrpsee::core::RpcResult<Ok>
            where
                F: FnOnce($err) -> (i32, M, Option<&'a [u8]>),
                M: Into<String>,
            {
                match self {
                    Ok(t) => Ok(t),
                    Err(err) => {
                        let (code, msg, data) = op(err);
                        Err($crate::error::rpc_err(code, msg, data))
                    }
                }
            }

            #[inline]
            fn map_invalid_params_err<'a, F, M>(self, op: F) -> jsonrpsee::core::RpcResult<Ok>
            where
                F: FnOnce($err) -> M,
                M: Into<String>,
            {
                self.map_err(|err| $crate::error::invalid_params_rpc_err(op(err)))
            }

            #[inline]
            fn map_internal_err<'a, F, M>(self, op: F) -> jsonrpsee::core::RpcResult<Ok>
            where
                F: FnOnce($err) -> M,
                M: Into<String>,
            {
                self.map_err(|err| $crate::error::internal_rpc_err(op(err)))
            }
        }
    };
}

impl_to_rpc_result!(RelayError);
impl_to_rpc_result!(AuthError);
impl_to_rpc_result!(QuoteError);
impl_to_rpc_result!(UserOpError);
impl_to_rpc_result!(KeysError);
impl_to_rpc_result!(StorageError);
impl_to_rpc_result!(TransportErrorKind);

/// Constructs an invalid params JSON-RPC error.
pub fn invalid_params_rpc_err(
    msg: impl Into<String>,
) -> jsonrpsee::types::error::ErrorObject<'static> {
    rpc_err(jsonrpsee::types::error::INVALID_PARAMS_CODE, msg, None)
}

/// Constructs an internal JSON-RPC error.
pub fn internal_rpc_err(msg: impl Into<String>) -> jsonrpsee::types::error::ErrorObject<'static> {
    rpc_err(jsonrpsee::types::error::INTERNAL_ERROR_CODE, msg, None)
}

/// Constructs an internal JSON-RPC error with code and message
pub fn rpc_error_with_code(
    code: i32,
    msg: impl Into<String>,
) -> jsonrpsee::types::error::ErrorObject<'static> {
    rpc_err(code, msg, None)
}

/// Constructs a JSON-RPC error, consisting of `code`, `message` and optional `data`.
pub fn rpc_err(
    code: i32,
    msg: impl Into<String>,
    data: Option<&[u8]>,
) -> jsonrpsee::types::error::ErrorObject<'static> {
    jsonrpsee::types::error::ErrorObject::owned(
        code,
        msg.into(),
        data.map(|data| {
            jsonrpsee::core::to_json_raw_value(&alloy::primitives::hex::encode_prefixed(data))
                .expect("serializing String can't fail")
        }),
    )
}
