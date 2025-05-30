use super::invalid_params;
use crate::types::KeyHash;
use thiserror::Error;

/// Errors related to authorization keys.
#[derive(Debug, Error)]
pub enum KeysError {
    /// The key type is not supported.
    #[error("only supports `p256`, `webauthnp256` and `secp256k1` key types")]
    UnsupportedKeyType,
    /// The p256 key type is only supported as session key.
    #[error("`p256` can only be used as a session key, not admin.")]
    P256SessionKeyOnly,
    /// Missing at least one admin authorization key.
    #[error("should have at least one admin authorization key")]
    MissingAdminKey,
    /// Should only have admin authorization keys.
    #[error("should only have admin authorization keys")]
    OnlyAdminKeyAllowed,
    /// Unknown key hash.
    #[error("key hash {0} is unknown")]
    UnknownKeyHash(KeyHash),
}

impl From<KeysError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(err: KeysError) -> Self {
        match err {
            KeysError::UnsupportedKeyType
            | KeysError::P256SessionKeyOnly
            | KeysError::MissingAdminKey
            | KeysError::OnlyAdminKeyAllowed
            | KeysError::UnknownKeyHash { .. } => invalid_params(err.to_string()),
        }
    }
}
