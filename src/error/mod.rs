//! Relay error types.
mod asset;
use std::error::Error;

pub use asset::AssetError;

mod auth;
pub use auth::AuthError;

mod contracts;
pub use contracts::ContractErrors;

mod email;
pub use email::EmailError;

mod phone;
pub use phone::PhoneError;

mod keys;
pub use keys::KeysError;

mod intent;
pub use intent::IntentError;

mod merkle;
pub use merkle::MerkleError;

mod quote;
pub use quote::QuoteError;

mod storage;
pub use storage::StorageError;

use alloy::{
    primitives::{Address, Bytes, ChainId},
    providers::MulticallError,
    transports::TransportErrorKind,
};
use thiserror::Error;

/// The relay overarching error type.
#[derive(Debug, Error)]
pub enum RelayError {
    /// Errors related to assets.
    #[error(transparent)]
    Asset(#[from] AssetError),
    /// Errors related to 7702 authorizations.
    #[error(transparent)]
    Auth(#[from] Box<AuthError>),
    /// Errors related to quotes.
    #[error(transparent)]
    Quote(#[from] QuoteError),
    /// Errors related to intents.
    #[error(transparent)]
    Intent(Box<IntentError>),
    /// Errors related to authorization keys.
    #[error(transparent)]
    Keys(#[from] KeysError),
    /// Errors related to storage.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// The chain is not supported.
    #[error("unsupported chain {0}")]
    UnsupportedChain(ChainId),
    /// The orchestrator is not supported.
    #[error("unsupported orchestrator {0}")]
    UnsupportedOrchestrator(Address),
    /// The asset is not supported.
    #[error("unsupported asset {asset} on chain {chain}")]
    UnsupportedAsset {
        /// The address of the asset that is not supported.
        asset: Address,
        /// The chain ID where the asset is not supported.
        chain: ChainId,
    },
    /// An error occurred during ABI encoding/decoding.
    #[error(transparent)]
    AbiError(#[from] alloy::sol_types::Error),
    /// An error occurred talking to RPC.
    #[error("{}", format_rpc_error(.0))]
    RpcError(#[from] alloy::transports::RpcError<TransportErrorKind>),
    /// Contract error.
    #[error(transparent)]
    ContractError(#[from] alloy::contract::Error),
    /// The relay is unhealthy.
    #[error("service is unhealthy")]
    Unhealthy,
    /// An internal error occurred.
    #[error(transparent)]
    InternalError(#[from] eyre::Error),
    /// Settlement-related errors.
    #[error(transparent)]
    Settlement(#[from] crate::interop::SettlementError),
}

impl RelayError {
    /// Creates an [`RelayError::InternalError`] from an error.
    pub fn internal(err: impl Error + Send + Sync + 'static) -> Self {
        Self::InternalError(err.into())
    }

    /// Creates an [`RelayError::InternalError`] from a message.
    pub fn internal_msg(msg: impl Into<String>) -> Self {
        Self::InternalError(eyre::eyre!(msg.into()))
    }
}

impl From<reqwest::Error> for RelayError {
    fn from(err: reqwest::Error) -> Self {
        Self::InternalError(err.into())
    }
}

impl From<IntentError> for RelayError {
    fn from(err: IntentError) -> Self {
        Self::Intent(Box::new(err))
    }
}

impl From<AuthError> for RelayError {
    fn from(err: AuthError) -> Self {
        Self::Auth(err.boxed())
    }
}

impl From<MulticallError> for RelayError {
    fn from(err: MulticallError) -> Self {
        match err {
            MulticallError::TransportError(err) => Self::RpcError(err),
            MulticallError::DecodeError(err) => Self::AbiError(err),
            _ => Self::InternalError(err.into()),
        }
    }
}

impl From<RelayError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(err: RelayError) -> Self {
        match err {
            RelayError::Asset(inner) => inner.into(),
            RelayError::Auth(inner) => (*inner).into(),
            RelayError::Quote(inner) => inner.into(),
            RelayError::Intent(inner) => (*inner).into(),
            RelayError::Keys(inner) => inner.into(),
            RelayError::Storage(inner) => inner.into(),
            RelayError::UnsupportedChain(_)
            | RelayError::AbiError(_)
            | RelayError::RpcError(_)
            | RelayError::ContractError(_)
            | RelayError::UnsupportedOrchestrator(_)
            | RelayError::Unhealthy
            | RelayError::UnsupportedAsset { .. }
            | RelayError::InternalError(_)
            | RelayError::Settlement(_) => internal_rpc(err.to_string()),
        }
    }
}

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

/// Formats an RPC error with detailed information from the error response.
fn format_rpc_error(err: &alloy::transports::RpcError<TransportErrorKind>) -> String {
    // Check if there's a JSON-RPC error response with detailed message
    if let Some(error_resp) = err.as_error_resp() {
        format!("RPC error: {} (code: {})", error_resp.message, error_resp.code)
    } else {
        // Fall back to default formatting
        err.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_error_formatting_with_error_response() {
        // Create a mock error payload similar to what Alchemy would return
        let error_payload = alloy::rpc::json_rpc::ErrorPayload {
            code: 429,
            message: "Monthly capacity limit exceeded. Visit https://dashboard.alchemy.com/settings/billing...".into(),
            data: None,
        };

        // Create an RpcError from the error payload
        let rpc_error: alloy::transports::RpcError<TransportErrorKind> = alloy::transports::RpcError::ErrorResp(error_payload);
        
        // Convert to RelayError
        let relay_error = RelayError::RpcError(rpc_error);
        
        // Check that the error message includes the detailed message
        let error_string = relay_error.to_string();
        assert!(error_string.contains("Monthly capacity limit exceeded"), "Error string should contain detailed message: {}", error_string);
        assert!(error_string.contains("429"), "Error string should contain error code: {}", error_string);
    }
}
