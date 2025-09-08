use super::invalid_params;
use crate::types::KeyHash;
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
    /// Too many admin authorization keys.
    #[error("maximum of one admin authorization key allowed")]
    TooManyAdminKeys,
    /// Too many keys.
    #[error("maximum of two authorization keys allowed")]
    TooManyKeys,
    /// Precalls are only allowed to modify one key to ensure correct ordering.
    #[error("precall can't modify multiple keys")]
    PrecallConflictingKeys,
    /// Should only have admin authorization keys.
    #[error("should only have admin authorization keys")]
    OnlyAdminKeyAllowed,
    /// Invalid signature.
    #[error("invalid signature")]
    InvalidSignature,
    /// Unknown key hash.
    #[error("key hash {0} is unknown")]
    UnknownKeyHash(KeyHash),
}

impl From<KeysError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(err: KeysError) -> Self {
        match err {
            KeysError::UnsupportedKeyType
            | KeysError::MissingAdminKey
            | KeysError::TooManyAdminKeys
            | KeysError::TooManyKeys
            | KeysError::PrecallConflictingKeys
            | KeysError::OnlyAdminKeyAllowed
            | KeysError::InvalidSignature
            | KeysError::UnknownKeyHash { .. } => invalid_params(err.to_string()),
        }
    }
}
