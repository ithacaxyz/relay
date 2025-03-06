//! Relay storage implementation in-memory. For testing only.

use super::{StorageApi, StorageError};
use crate::types::PREPAccount;
use alloy::primitives::Address;
use dashmap::{DashMap, Entry};

/// [`StorageApi`] implementation in-memory. Used for testing
#[derive(Debug, Default)]
pub struct InMemoryStorage {
    storage: DashMap<Address, PREPAccount>,
}

impl StorageApi for InMemoryStorage {
    fn read_prep(&self, address: &Address) -> Option<PREPAccount> {
        self.storage.get(address).map(|acc| (*acc).clone())
    }

    fn write_prep(&self, account: &PREPAccount) -> Result<(), StorageError> {
        match self.storage.entry(account.address) {
            Entry::Occupied(_) => Err(StorageError::AccountAlreadyExists(account.address)),
            Entry::Vacant(entry) => {
                entry.insert(account.clone());
                Ok(())
            }
        }
    }
}
