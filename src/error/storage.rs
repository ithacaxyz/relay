use alloy::primitives::Address;
use super::invalid_params;

/// Errors returned by [`Storage`].
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// The PREPAccount already exists.
    #[error("PREPaccount with address {0} already exists.")]
    AccountAlreadyExists(Address),
}

impl From<StorageError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(err: StorageError) -> Self {
        match err {
            StorageError::AccountAlreadyExists(..) => invalid_params(err),
        }
    }
}
