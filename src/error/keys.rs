use super::{internal_rpc, invalid_params};
use alloy::primitives::Address;
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
}

impl From<KeysError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(err: KeysError) -> Self {
        match err {
            KeysError::UnsupportedKeyType | KeysError::MissingAdminKey => invalid_params(err),
            KeysError::InvalidRegistryData(_) => internal_rpc(err),
        }
    }
}
