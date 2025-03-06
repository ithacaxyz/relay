//! Relay storage

mod api;
pub use api::StorageApi;
mod error;
pub use error::StorageError;
mod memory;

use crate::types::PREPAccount;
use alloy::primitives::Address;
use std::sync::Arc;

/// Relay storage interface.
#[derive(Debug, Clone)]
pub struct RelayStorage {
    inner: Arc<dyn StorageApi>,
}

impl RelayStorage {
    /// Create [`RelayStorage`] with a in-memory backend. Used for testing only.
    pub fn in_memory() -> Self {
        Self { inner: Arc::new(memory::InMemoryStorage::default()) }
    }
}

impl StorageApi for RelayStorage {
    fn read_prep(&self, address: &Address) -> Option<PREPAccount> {
        self.inner.read_prep(address)
    }

    fn write_prep(&self, account: &PREPAccount) -> Result<(), StorageError> {
        self.inner.write_prep(account)
    }
}
