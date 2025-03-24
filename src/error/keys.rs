use super::{internal_rpc, invalid_params};
use alloy::primitives::{Address, PrimitiveSignature};
use thiserror::Error;

/// Errors related to authorization keys.
#[derive(Debug, Error)]
pub enum KeysError {
    /// The key type is not supported.
    #[error("only supports `p256`, `webauthnp256` and `secp256k1` key types")]
    UnsupportedKeyType,
    /// Missing at least one admin authorization key.
    #[error("should have at least one admin authorization key")]
    MissingAdminKey,
    /// Invalid account key registry data.
    #[error("invalid account key registry data for ID {0}")]
    InvalidRegistryData(Address),
    /// Key identifier already in use on account registry.
    #[error("key identifier already taken: {0}")]
    TakenKeyId(Address),
    /// Invalid key identifier signature.
    #[error("invalid key identifier signature: {0}")]
    InvalidKeyIdSignature(PrimitiveSignature),
    /// Unexpected key identifier.
    #[error("invalid key identifier: expected {expected}, got {got}")]
    UnexpectedKeyId {
        /// The ID expected.
        expected: Address,
        /// The ID in the request.
        got: Address,
    },
}

impl From<KeysError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(err: KeysError) -> Self {
        match err {
            KeysError::UnsupportedKeyType
            | KeysError::MissingAdminKey
            | KeysError::TakenKeyId { .. }
            | KeysError::UnexpectedKeyId { .. }
            | KeysError::InvalidKeyIdSignature { .. } => invalid_params(err.to_string()),
            KeysError::InvalidRegistryData(_) => internal_rpc(err.to_string()),
        }
    }
}
