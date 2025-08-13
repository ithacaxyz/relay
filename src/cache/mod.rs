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
    providers::Provider,
};
use dashmap::DashMap;
use std::sync::Arc;
use tracing::debug;

use crate::types::Orchestrator;

/// Internal cache implementation that is shared across instances.
#[derive(Debug)]
struct CacheInner {
    /// Static cache for contract code (never expires - code is immutable)
    pub code_cache: DashMap<Address, Bytes>,
    /// Static cache for delegation implementations (rarely changes in production)
    delegation_cache: DashMap<Address, Address>,
    /// Cache for EIP712Domains: key is (orchestrator_address, chain_id, is_multichain)
    /// The is_multichain bool differentiates between multichain and single-chain domains
    eip712_domain_cache: DashMap<(Address, ChainId, bool), Eip712Domain>,
}

/// Thread-safe cache for RPC results with factory methods for creating cached contract instances.
///
/// This type uses a shareable container pattern to avoid explicit Arc usage in client code.
#[derive(Debug, Clone)]
pub struct RpcCache(Arc<CacheInner>);

impl RpcCache {
    /// Create a new RPC cache instance.
    pub fn new() -> Self {
        Self(Arc::new(CacheInner {
            code_cache: DashMap::new(),
            delegation_cache: DashMap::new(),
            eip712_domain_cache: DashMap::new(),
        }))
    }

    /// Factory method to create an Orchestrator instance with cache support.
    ///
    /// This method encapsulates the creation of cached contract instances,
    /// avoiding the need to pass around Optional cache references.
    pub fn get_orchestrator<P: Provider>(&self, address: Address, provider: P) -> Orchestrator<P> {
        Orchestrator::new(address, provider).with_cache(self.clone())
    }

    /// Get cached contract code (static, never expires).
    pub fn get_code(&self, address: &Address) -> Option<Bytes> {
        let entry = self.0.code_cache.get(address)?;
        debug!(address = %address, "Code cache HIT");
        Some(entry.value().clone())
    }

    /// Cache contract code for the instance (code is immutable).
    pub fn set_code(&self, address: Address, code: Bytes) {
        debug!(address = %address, code_len = code.len(), "Caching contract code (static)");
        self.0.code_cache.insert(address, code);
    }

    /// Get cached delegation implementation, or None if not cached.
    pub fn get_delegation(&self, account: &Address) -> Option<Address> {
        let entry = self.0.delegation_cache.get(account)?;
        debug!(account = %account, delegation = %entry.value(), "Delegation cache HIT");
        Some(*entry.value())
    }

    /// Cache delegation implementation for the instance.
    pub fn set_delegation(&self, account: Address, implementation: Address) {
        debug!(account = %account, implementation = %implementation, "Caching delegation implementation");
        self.0.delegation_cache.insert(account, implementation);
    }

    /// Clear all delegation cache entries (useful for tests).
    pub fn clear_delegation_cache(&self) {
        self.0.delegation_cache.clear();
    }

    /// Get cached EIP712Domain for an orchestrator on a specific chain.
    /// The multichain flag determines whether to retrieve multichain or single-chain variant.
    pub fn get_eip712_domain(
        &self,
        orchestrator: &Address,
        chain_id: ChainId,
        multichain: bool,
    ) -> Option<Eip712Domain> {
        let entry = self.0.eip712_domain_cache.get(&(*orchestrator, chain_id, multichain))?;
        debug!(orchestrator = %orchestrator, chain_id, multichain, "EIP712Domain cache HIT");
        Some(entry.value().clone())
    }

    /// Cache EIP712Domain for an orchestrator on a specific chain.
    /// The multichain flag determines whether this is a multichain or single-chain variant.
    pub fn set_eip712_domain(
        &self,
        orchestrator: Address,
        chain_id: ChainId,
        domain: Eip712Domain,
        multichain: bool,
    ) {
        debug!(orchestrator = %orchestrator, chain_id, multichain, "Caching EIP712Domain");
        self.0.eip712_domain_cache.insert((orchestrator, chain_id, multichain), domain);
    }

    /// Check if we should skip an address in multicall because it's cached.
    /// Returns true if the code is cached and non-empty (contract exists).
    pub fn should_skip_in_multicall(&self, address: &Address) -> bool {
        if let Some(code) = self.get_code(address) {
            debug!(address = %address, "Skipping in multicall - cached");
            !code.is_empty()
        } else {
            false
        }
    }

    /// Get the number of cached code entries.
    pub fn code_cache_size(&self) -> usize {
        self.0.code_cache.len()
    }

    /// Get the number of cached delegation entries.
    pub fn delegation_cache_size(&self) -> usize {
        self.0.delegation_cache.len()
    }

    /// Prepare a list of addresses for multicall by filtering out cached entries.
    /// Returns a vector of addresses that need to be fetched.
    pub fn prepare_multicall_batch(&self, addresses: &[Address]) -> Vec<Address> {
        addresses.iter().filter(|addr| !self.should_skip_in_multicall(addr)).copied().collect()
    }

    /// Merge multicall results with cached values.
    /// Takes the original list of addresses and the filtered results from multicall.
    /// Returns a vector with all values in the original order.
    pub fn merge_results<T: Clone>(
        &self,
        addresses: &[Address],
        multicall_results: Vec<T>,
        get_cached: impl Fn(&Address) -> Option<T>,
    ) -> Vec<Option<T>> {
        let mut result_iter = multicall_results.into_iter();
        addresses
            .iter()
            .map(|addr| {
                if self.should_skip_in_multicall(addr) {
                    // Use cached value
                    get_cached(addr)
                } else {
                    // Use multicall result
                    result_iter.next()
                }
            })
            .collect()
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

        // Test caching for chain 1 (single-chain)
        assert_eq!(cache.get_eip712_domain(&orchestrator, chain_id_1, false), None);
        cache.set_eip712_domain(orchestrator, chain_id_1, domain_chain_1.clone(), false);
        assert_eq!(
            cache.get_eip712_domain(&orchestrator, chain_id_1, false),
            Some(domain_chain_1.clone())
        );

        // Test caching for chain 2 (single-chain)
        assert_eq!(cache.get_eip712_domain(&orchestrator, chain_id_2, false), None);
        cache.set_eip712_domain(orchestrator, chain_id_2, domain_chain_2.clone(), false);
        assert_eq!(
            cache.get_eip712_domain(&orchestrator, chain_id_2, false),
            Some(domain_chain_2.clone())
        );

        // Verify different chains have separate cache entries
        assert_eq!(
            cache.get_eip712_domain(&orchestrator, chain_id_1, false),
            Some(domain_chain_1.clone())
        );
        assert_eq!(
            cache.get_eip712_domain(&orchestrator, chain_id_2, false),
            Some(domain_chain_2.clone())
        );

        // Test multichain variants are cached separately
        let domain_multichain = Eip712Domain::new(
            Some("TestDomain".into()),
            Some("1.0.0".into()),
            None, // No chain ID for multichain
            Some(orchestrator),
            None,
        );

        assert_eq!(cache.get_eip712_domain(&orchestrator, chain_id_1, true), None);
        cache.set_eip712_domain(orchestrator, chain_id_1, domain_multichain.clone(), true);
        assert_eq!(
            cache.get_eip712_domain(&orchestrator, chain_id_1, true),
            Some(domain_multichain)
        );

        // Verify single-chain and multichain entries are separate
        assert_eq!(cache.get_eip712_domain(&orchestrator, chain_id_1, false), Some(domain_chain_1));
        assert_eq!(cache.get_eip712_domain(&orchestrator, chain_id_2, false), Some(domain_chain_2));
    }

    #[test]
    fn test_multicall_batch_preparation() {
        let cache = RpcCache::new();

        // Set up test addresses
        let addr1 = address!("1111111111111111111111111111111111111111");
        let addr2 = address!("2222222222222222222222222222222222222222");
        let addr3 = address!("3333333333333333333333333333333333333333");

        // Cache code for addr2 (should be skipped)
        cache.set_code(addr2, bytes!("608060405234801561001057600080fd5b50"));

        // Test batch preparation
        let addresses = vec![addr1, addr2, addr3];
        let batch = cache.prepare_multicall_batch(&addresses);

        // Should only include addr1 and addr3 (addr2 is cached)
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0], addr1);
        assert_eq!(batch[1], addr3);
    }

    #[test]
    fn test_merge_results() {
        let cache = RpcCache::new();

        // Set up test addresses
        let addr1 = address!("1111111111111111111111111111111111111111");
        let addr2 = address!("2222222222222222222222222222222222222222");
        let addr3 = address!("3333333333333333333333333333333333333333");

        // Cache code for addr2
        let cached_code = bytes!("608060405234801561001057600080fd5b50");
        cache.set_code(addr2, cached_code.clone());

        // Simulate multicall results (only for non-cached addresses)
        let multicall_results = vec![
            bytes!("1111"), // Result for addr1
            bytes!("3333"), // Result for addr3
        ];

        // Merge results
        let addresses = vec![addr1, addr2, addr3];
        let merged =
            cache.merge_results(&addresses, multicall_results, |addr| cache.get_code(addr));

        // Verify merged results
        assert_eq!(merged.len(), 3);
        assert_eq!(merged[0], Some(bytes!("1111"))); // addr1 from multicall
        assert_eq!(merged[1], Some(cached_code)); // addr2 from cache
        assert_eq!(merged[2], Some(bytes!("3333"))); // addr3 from multicall
    }
}
