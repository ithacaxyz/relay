use super::internal_rpc;
use crate::error::invalid_params;
use alloy::primitives::Address;

/// Errors returned by [`Storage`].
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// The account does not exist.
    #[error("Account with address {0} does not exist in storage.")]
    AccountDoesNotExist(Address),
    /// Can't lock liquidity.
    #[error("can't lock liquidity")]
    CantLockLiquidity,
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
            StorageError::AccountDoesNotExist(..) => invalid_params(err.to_string()),
            StorageError::CantLockLiquidity => internal_rpc("can't lock liquidity"),
            StorageError::SerdeError(..) => internal_rpc("an internal error occurred"),
            StorageError::InternalError(..) => internal_rpc("an internal error occurred"),
        }
    }
}
