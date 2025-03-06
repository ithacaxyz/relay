use alloy::primitives::Address;

/// Errors returned by [`Storage`].
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// The PREPAccount already exists.
    #[error("PREPaccount with address {0} already exists.")]
    AccountAlreadyExists(Address),
}
