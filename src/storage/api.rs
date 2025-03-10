//! Relay storage api.

use super::StorageError;
use crate::types::PREPAccount;
use alloy::primitives::Address;
use async_trait::async_trait;
use std::fmt::Debug;

/// Type alias for `Result<T, StorageError>`
pub type Result<T> = core::result::Result<T, StorageError>;

/// Storage API.
#[async_trait]
pub trait StorageApi: Debug + Send + Sync {
    /// Reads [`PREPAccount`] from storage.
    async fn read_prep(&self, address: &Address) -> Result<Option<PREPAccount>>;

    /// Writes [`PREPAccount`] to storage.
    async fn write_prep(&self, account: &PREPAccount) -> Result<()>;
}
