//! RPC caching infrastructure for optimizing chain interactions.
//!
//! This module provides thread-safe caching mechanisms for reducing redundant RPC calls.
//! All cached values persist for the lifetime of the application since they represent
//! static or rarely-changing blockchain data.

#[cfg(test)]
use alloy::primitives::U256;
use alloy::{
    dyn_abi::Eip712Domain,
    primitives::{Address, Bytes, ChainId},
};
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
    /// Static cache for delegation implementations (rarely changes in production)
    delegation_cache: DashMap<Address, Address>,
    /// Cache for EIP712Domains: key is (orchestrator_address, chain_id)
    /// The orchestrator's EIP712Domain is fixed per chain
    eip712_domain_cache: DashMap<(Address, ChainId), Eip712Domain>,
}

impl RpcCache {
    /// Create a new RPC cache instance.
    pub fn new() -> Self {
        Self {
            chain_id: OnceLock::new(),
            code_cache: DashMap::new(),
            delegation_cache: DashMap::new(),
            eip712_domain_cache: DashMap::new(),
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

    /// Cache contract code for the instance (code is immutable).
    pub fn set_code(&self, address: Address, code: Bytes) {
        debug!(address = %address, code_len = code.len(), "Caching contract code (static)");
        self.code_cache.insert(address, code);
    }

    /// Get cached delegation implementation, or None if not cached.
    pub fn get_delegation(&self, account: &Address) -> Option<Address> {
        let entry = self.delegation_cache.get(account)?;
        debug!(account = %account, delegation = %entry.value(), "Delegation cache HIT");
        Some(*entry.value())
    }

    /// Cache delegation implementation for the instance.
    pub fn set_delegation(&self, account: Address, implementation: Address) {
        debug!(account = %account, implementation = %implementation, "Caching delegation implementation");
        self.delegation_cache.insert(account, implementation);
    }

    /// Clear all delegation cache entries (useful for tests).
    pub fn clear_delegation_cache(&self) {
        self.delegation_cache.clear();
    }

    /// Get cached EIP712Domain for an orchestrator on a specific chain.
    pub fn get_eip712_domain(
        &self,
        orchestrator: &Address,
        chain_id: ChainId,
    ) -> Option<Eip712Domain> {
        let entry = self.eip712_domain_cache.get(&(*orchestrator, chain_id))?;
        debug!(orchestrator = %orchestrator, chain_id, "EIP712Domain cache HIT");
        Some(entry.value().clone())
    }

    /// Cache EIP712Domain for an orchestrator on a specific chain.
    pub fn set_eip712_domain(
        &self,
        orchestrator: Address,
        chain_id: ChainId,
        domain: Eip712Domain,
    ) {
        debug!(orchestrator = %orchestrator, chain_id, "Caching EIP712Domain");
        self.eip712_domain_cache.insert((orchestrator, chain_id), domain);
    }
}

impl Default for RpcCache {
    fn default() -> Self {
        Self::new()
    }
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

        // Test delegation caching
        let account = address!("1234567890123456789012345678901234567890");
        let implementation = address!("abcdefabcdefabcdefabcdefabcdefabcdefabcd");

        assert_eq!(cache.get_delegation(&account), None);
        cache.set_delegation(account, implementation);
        assert_eq!(cache.get_delegation(&account), Some(implementation));

        // Test cache clearing
        cache.clear_delegation_cache();
        assert_eq!(cache.get_delegation(&account), None);
    }

    #[test]
    fn test_eip712_domain_caching() {
        let cache = RpcCache::new();
        let orchestrator = address!("1234567890123456789012345678901234567890");
        let chain_id_1 = ChainId::from(1u64);
        let chain_id_2 = ChainId::from(2u64);

        // Create domains for different chains
        let domain_chain_1 = Eip712Domain::new(
            Some("TestDomain".into()),
            Some("1.0.0".into()),
            Some(U256::from(chain_id_1)),
            Some(orchestrator),
            None,
        );

        let domain_chain_2 = Eip712Domain::new(
            Some("TestDomain".into()),
            Some("1.0.0".into()),
            Some(U256::from(chain_id_2)),
            Some(orchestrator),
            None,
        );

        // Test caching for chain 1
        assert_eq!(cache.get_eip712_domain(&orchestrator, chain_id_1), None);
        cache.set_eip712_domain(orchestrator, chain_id_1, domain_chain_1.clone());
        assert_eq!(
            cache.get_eip712_domain(&orchestrator, chain_id_1),
            Some(domain_chain_1.clone())
        );

        // Test caching for chain 2
        assert_eq!(cache.get_eip712_domain(&orchestrator, chain_id_2), None);
        cache.set_eip712_domain(orchestrator, chain_id_2, domain_chain_2.clone());
        assert_eq!(
            cache.get_eip712_domain(&orchestrator, chain_id_2),
            Some(domain_chain_2.clone())
        );

        // Verify different chains have separate cache entries
        assert_eq!(cache.get_eip712_domain(&orchestrator, chain_id_1), Some(domain_chain_1));
        assert_eq!(cache.get_eip712_domain(&orchestrator, chain_id_2), Some(domain_chain_2));
    }
}
