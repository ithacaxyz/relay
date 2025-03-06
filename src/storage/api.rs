//! Relay storage api.

use super::StorageError;
use crate::types::PREPAccount;
use alloy::primitives::Address;
use std::fmt::Debug;

/// Storage API.
pub trait StorageApi: Debug + Send + Sync {
    /// Reads [`PREPAccount`] from storage.
    fn read_prep(&self, address: &Address) -> Option<PREPAccount>;

    /// Writes [`PREPAccount`] to storage.
    fn write_prep(&self, account: &PREPAccount) -> Result<(), StorageError>;
}
