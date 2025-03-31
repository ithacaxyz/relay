use super::{internal_rpc, invalid_params};
use alloy::primitives::Address;

/// Errors returned by [`Storage`].
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// The PREPAccount already exists.
    #[error("PREPaccount with address {0} already exists.")]
    AccountAlreadyExists(Address),
    /// A deserialization error occurred.
    #[error("a deserialization error occurred")]
    SerdeError(#[from] serde_json::Error),
    /// An internal error occurred.
    #[error("an internal error occurred")]
    InternalError(#[from] eyre::Error),
}

impl From<StorageError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(err: StorageError) -> Self {
        match err {
            StorageError::AccountAlreadyExists(..) => invalid_params(err.to_string()),
            StorageError::SerdeError(..) => internal_rpc("an internal error occurred"),
            StorageError::InternalError(..) => internal_rpc("an internal error occurred"),
        }
    }
}
