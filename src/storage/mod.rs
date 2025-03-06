//! Relay storage

mod api;
pub use api::StorageApi;

mod memory;
pub use memory::InMemoryStorage;
