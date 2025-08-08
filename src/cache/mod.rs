//! RPC caching infrastructure for optimizing chain interactions.
//!
//! This module provides thread-safe caching mechanisms for reducing redundant RPC calls.
//! All cached values persist for the lifetime of the application since they represent
//! static or rarely-changing blockchain data.

use alloy::primitives::{Address, Bytes, ChainId};
use dashmap::DashMap;
use std::sync::OnceLock;
use tracing::{debug, trace};

/// Thread-safe cache for RPC results.
#[derive(Debug)]
pub struct RpcCache {
    /// Static cache for chain ID (never expires)
    chain_id: OnceLock<ChainId>,
    /// Static cache for contract code (never expires - code is immutable)
    pub code_cache: DashMap<Address, Bytes>,
    /// Static cache for delegation implementations (per account)
    pub delegation_cache: DashMap<Address, Address>,
}

impl RpcCache {
    /// Create a new RPC cache instance.
    pub fn new() -> Self {
        Self {
            chain_id: OnceLock::new(),
            code_cache: DashMap::new(),
            delegation_cache: DashMap::new(),
        }
    }

    /// Get cached chain ID, or None if not cached.
    pub fn get_chain_id(&self) -> Option<ChainId> {
        self.chain_id.get().copied()
    }

    /// Cache the chain ID (never expires).
    pub fn set_chain_id(&self, chain_id: ChainId) -> ChainId {
        trace!(chain_id = %chain_id, "Caching chain ID");
        *self.chain_id.get_or_init(|| chain_id)
    }

    /// Get cached contract code (static, never expires).
    pub fn get_code(&self, address: &Address) -> Option<Bytes> {
        let entry = self.code_cache.get(address)?;
        debug!(address = %address, "Code cache HIT");
        Some(entry.value().clone())
    }

    /// Cache contract code permanently (code is immutable).
    pub fn set_code(&self, address: Address, code: Bytes) {
        debug!(address = %address, code_len = code.len(), "Caching contract code (static)");
        self.code_cache.insert(address, code);
    }

    /// Get cached delegation implementation.
    pub fn get_delegation_impl(&self, account: &Address) -> Option<Address> {
        let entry = self.delegation_cache.get(account)?;
        debug!(account = %account, "Delegation impl cache HIT");
        Some(*entry.value())
    }

    /// Cache delegation implementation permanently.
    pub fn set_delegation_impl(&self, account: Address, delegation: Address) {
        debug!(account = %account, delegation = %delegation, "Caching delegation implementation");
        self.delegation_cache.insert(account, delegation);
    }

    /// Get cache statistics for monitoring.
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            chain_id_cached: self.chain_id.get().is_some(),
            code_cache_size: self.code_cache.len(),
            delegation_cache_size: self.delegation_cache.len(),
        }
    }
}

impl Default for RpcCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about cache usage.
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Whether chain ID is cached
    pub chain_id_cached: bool,
    /// Number of cached contract codes
    pub code_cache_size: usize,
    /// Number of cached delegation implementations
    pub delegation_cache_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{address, bytes};

    #[test]
    fn test_static_caches() {
        let cache = RpcCache::new();

        // Test chain ID caching
        assert_eq!(cache.get_chain_id(), None);
        let chain_id = ChainId::from(1u64);
        cache.set_chain_id(chain_id);
        assert_eq!(cache.get_chain_id(), Some(chain_id));
    }

    #[test]
    fn test_code_caching() {
        let cache = RpcCache::new();

        // Test code caching
        let addr = address!("1234567890123456789012345678901234567890");
        let code = bytes!("608060405234801561001057600080fd5b50");

        assert_eq!(cache.get_code(&addr), None);
        cache.set_code(addr, code.clone());
        assert_eq!(cache.get_code(&addr), Some(code));
    }

    #[test]
    fn test_delegation_caching() {
        let cache = RpcCache::new();

        // Test delegation implementation caching
        let account = address!("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd");
        let delegation = address!("1111111111111111111111111111111111111111");

        assert_eq!(cache.get_delegation_impl(&account), None);
        cache.set_delegation_impl(account, delegation);
        assert_eq!(cache.get_delegation_impl(&account), Some(delegation));
    }

    #[test]
    fn test_cache_stats() {
        let cache = RpcCache::new();

        let stats = cache.stats();
        assert!(!stats.chain_id_cached);
        assert_eq!(stats.code_cache_size, 0);
        assert_eq!(stats.delegation_cache_size, 0);

        // Add some cached values
        cache.set_chain_id(ChainId::from(1u64));
        let addr = address!("1234567890123456789012345678901234567890");
        let code = bytes!("608060405234801561001057600080fd5b50");
        cache.set_code(addr, code);
        let account = address!("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd");
        let delegation = address!("1111111111111111111111111111111111111111");
        cache.set_delegation_impl(account, delegation);

        let stats = cache.stats();
        assert!(stats.chain_id_cached);
        assert_eq!(stats.code_cache_size, 1);
        assert_eq!(stats.delegation_cache_size, 1);
    }
}