//! Relay storage

mod api;
pub use api::StorageApi;
mod error;
use async_trait::async_trait;
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

#[async_trait]
impl StorageApi for RelayStorage {
    async fn read_prep(&self, address: &Address) -> api::Result<Option<PREPAccount>> {
        self.inner.read_prep(address).await
    }

    async fn write_prep(&self, account: &PREPAccount) -> api::Result<()> {
        self.inner.write_prep(account).await
    }
}
