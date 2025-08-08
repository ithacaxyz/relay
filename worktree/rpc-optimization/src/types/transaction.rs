use crate::transactions::TransactionServiceHandle;
use alloy::primitives::{ChainId, map::HashMap};
use std::sync::Arc;

/// Transaction service handles for multiple chains
#[derive(Debug, Clone)]
pub struct TransactionServiceHandles(Arc<HashMap<ChainId, TransactionServiceHandle>>);

impl TransactionServiceHandles {
    /// Create new TransactionServiceHandles
    pub fn new(handles: HashMap<ChainId, TransactionServiceHandle>) -> Self {
        Self(Arc::new(handles))
    }

    /// Get a transaction service handle by chain ID
    pub fn get(&self, chain_id: &ChainId) -> Option<&TransactionServiceHandle> {
        self.0.get(chain_id)
    }
}
