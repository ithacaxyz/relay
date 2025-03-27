use super::invalid_params;
use crate::types::KeyHash;
use alloy::primitives::{Address, Bytes};
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
    /// Should only have admin authorization keys.
    #[error("should only have admin authorization keys")]
    OnlyAdminKeyAllowed,
    /// Unknown key id.
    #[error("key id {0} is unknown")]
    UnknownKeyId(Address),
    /// Key identifier already in use on account registry.
    #[error("key identifier already taken: {0}")]
    TakenKeyId(Address),
    /// Invalid key identifier signature.
    #[error("invalid key identifier signature: {0}")]
    InvalidKeyIdSignature(Bytes),
    /// Unexpected key identifier.
    #[error("invalid key identifier: expected {expected}, got {got}")]
    UnexpectedKeyId {
        /// The ID expected.
        expected: Address,
        /// The ID in the request.
        got: Address,
    },
    /// Missing key id signature.
    #[error("missing key id signature for key hash {0}")]
    MissingKeyID(KeyHash),
}

impl From<KeysError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(err: KeysError) -> Self {
        match err {
            KeysError::UnsupportedKeyType
            | KeysError::MissingKeyID { .. }
            | KeysError::MissingAdminKey
            | KeysError::OnlyAdminKeyAllowed
            | KeysError::TakenKeyId { .. }
            | KeysError::UnexpectedKeyId { .. }
            | KeysError::UnknownKeyId { .. }
            | KeysError::InvalidKeyIdSignature { .. } => invalid_params(err.to_string()),
        }
    }
}
