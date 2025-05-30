use super::internal_rpc;

/// Errors returned by [`Storage`].
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
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
            StorageError::SerdeError(..) => internal_rpc("an internal error occurred"),
            StorageError::InternalError(..) => internal_rpc("an internal error occurred"),
        }
    }
}
