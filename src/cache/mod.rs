//! RPC caching infrastructure for optimizing chain interactions.
//!
//! This module provides thread-safe caching mechanisms for reducing redundant RPC calls:
//! - Static values that never change (chain ID, delegation implementation)
//! - TTL-based caching for frequently changing values (fees, code, keys)
//! - Request deduplication for concurrent identical calls

use alloy::primitives::{Address, Bytes, ChainId, U256};
use dashmap::DashMap;
use std::{
    hash::Hash,
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};
use tokio::sync::broadcast;
use tracing::{debug, trace};

/// Thread-safe cache for RPC results with TTL support and request deduplication.
#[derive(Debug)]
pub struct RpcCache {
    /// Static cache for chain ID (never expires)
    chain_id: OnceLock<ChainId>,
    /// Static cache for delegation implementation address (never expires)
    delegation_impl: OnceLock<Address>,
    /// TTL cache for fee estimates
    fee_cache: DashMap<String, CachedValue<U256>>,
    /// TTL cache for contract code
    code_cache: DashMap<Address, CachedValue<Bytes>>,
    /// TTL cache for account keys
    keys_cache: DashMap<Address, CachedValue<Vec<u8>>>, // Generic bytes for keys
    /// TTL cache for fee history data
    fee_history_cache: DashMap<String, CachedValue<serde_json::Value>>,
    /// Request deduplication for eth_call
    pending_calls: DashMap<CallKey, Arc<broadcast::Sender<CallResult>>>,
}

/// A cached value with TTL support.
#[derive(Debug, Clone)]
pub struct CachedValue<T> {
    /// The cached value
    pub value: T,
    /// When this value was cached
    cached_at: Instant,
    /// How long this value should be cached
    ttl: Duration,
}

impl<T> CachedValue<T> {
    /// Create a new cached value with the specified TTL.
    pub fn new(value: T, ttl: Duration) -> Self {
        Self { value, cached_at: Instant::now(), ttl }
    }

    /// Check if this cached value has expired.
    pub fn is_expired(&self) -> bool {
        self.cached_at.elapsed() > self.ttl
    }

    /// Get the value if it's still valid, otherwise return None.
    pub fn get_if_valid(&self) -> Option<&T> {
        if self.is_expired() { None } else { Some(&self.value) }
    }
}

/// Key for deduplicating eth_call requests.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallKey {
    /// Target contract address
    pub to: Address,
    /// Call data
    pub data: Bytes,
    /// Block number or tag
    pub block: String,
}

/// Result of an eth_call operation for deduplication.
pub type CallResult = Result<Bytes, String>;

impl RpcCache {
    /// Create a new RPC cache instance.
    pub fn new() -> Self {
        Self {
            chain_id: OnceLock::new(),
            delegation_impl: OnceLock::new(),
            fee_cache: DashMap::new(),
            code_cache: DashMap::new(),
            keys_cache: DashMap::new(),
            fee_history_cache: DashMap::new(),
            pending_calls: DashMap::new(),
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

    /// Get cached delegation implementation address, or None if not cached.
    pub fn get_delegation_impl(&self) -> Option<Address> {
        self.delegation_impl.get().copied()
    }

    /// Cache the delegation implementation address (never expires).
    pub fn set_delegation_impl(&self, addr: Address) -> Address {
        trace!(address = %addr, "Caching delegation implementation");
        *self.delegation_impl.get_or_init(|| addr)
    }

    /// Get cached fee estimate if valid.
    pub fn get_fee_estimate(&self, key: &str) -> Option<U256> {
        let entry = self.fee_cache.get(key)?;
        if let Some(value) = entry.get_if_valid() {
            debug!(key = key, "Fee estimate cache HIT");
            Some(*value)
        } else {
            debug!(key = key, "Fee estimate cache EXPIRED");
            // Clean up expired entry
            self.fee_cache.remove(key);
            None
        }
    }

    /// Cache a fee estimate with 2-minute TTL.
    pub fn set_fee_estimate(&self, key: String, value: U256) {
        debug!(key = %key, value = %value, "Caching fee estimate");
        self.fee_cache.insert(
            key,
            CachedValue::new(value, Duration::from_secs(120)), // 2 minutes
        );
    }

    /// Get cached contract code if valid.
    pub fn get_code(&self, address: &Address) -> Option<Bytes> {
        let entry = self.code_cache.get(address)?;
        if let Some(value) = entry.get_if_valid() {
            debug!(address = %address, "Code cache HIT");
            Some(value.clone())
        } else {
            debug!(address = %address, "Code cache EXPIRED");
            // Clean up expired entry
            self.code_cache.remove(address);
            None
        }
    }

    /// Cache contract code with long TTL (30 minutes).
    pub fn set_code(&self, address: Address, code: Bytes) {
        debug!(address = %address, code_len = code.len(), "Caching contract code");
        self.code_cache.insert(
            address,
            CachedValue::new(code, Duration::from_secs(1800)), // 30 minutes
        );
    }

    /// Get cached keys if valid.
    pub fn get_keys(&self, address: &Address) -> Option<Vec<u8>> {
        let entry = self.keys_cache.get(address)?;
        if let Some(value) = entry.get_if_valid() {
            debug!(address = %address, "Keys cache HIT");
            Some(value.clone())
        } else {
            debug!(address = %address, "Keys cache EXPIRED");
            // Clean up expired entry
            self.keys_cache.remove(address);
            None
        }
    }

    /// Cache keys with 10-minute TTL.
    pub fn set_keys(&self, address: Address, keys: Vec<u8>) {
        debug!(address = %address, keys_len = keys.len(), "Caching keys");
        self.keys_cache.insert(
            address,
            CachedValue::new(keys, Duration::from_secs(600)), // 10 minutes
        );
    }

    /// Get cached fee history if valid.
    pub fn get_fee_history(&self, key: &str) -> Option<serde_json::Value> {
        let entry = self.fee_history_cache.get(key)?;
        if let Some(value) = entry.get_if_valid() {
            debug!(key = key, "Fee history cache HIT");
            Some(value.clone())
        } else {
            debug!(key = key, "Fee history cache EXPIRED");
            // Clean up expired entry
            self.fee_history_cache.remove(key);
            None
        }
    }

    /// Cache fee history with 5-minute TTL.
    pub fn set_fee_history(&self, key: String, value: serde_json::Value) {
        debug!(key = %key, "Caching fee history");
        self.fee_history_cache.insert(
            key,
            CachedValue::new(value, Duration::from_secs(300)), // 5 minutes
        );
    }

    /// Get or create a broadcast channel for deduplicating eth_call requests.
    /// Returns None if a call is already in progress, Some(receiver) to wait for result.
    pub fn deduplicate_call(&self, call_key: CallKey) -> Option<broadcast::Receiver<CallResult>> {
        if let Some(existing) = self.pending_calls.get(&call_key) {
            debug!(to = %call_key.to, "Call deduplication HIT - waiting for existing call");
            Some(existing.subscribe())
        } else {
            // No existing call, caller should proceed and call complete_call when done
            None
        }
    }

    /// Start a new call deduplication entry. Returns the sender to broadcast results.
    pub fn start_call_deduplication(
        &self,
        call_key: CallKey,
    ) -> Arc<broadcast::Sender<CallResult>> {
        let (tx, _) = broadcast::channel(1);
        let tx = Arc::new(tx);
        self.pending_calls.insert(call_key, tx.clone());
        tx
    }

    /// Complete a call deduplication by broadcasting the result and cleaning up.
    pub fn complete_call_deduplication(&self, call_key: &CallKey, result: CallResult) {
        if let Some((_, sender)) = self.pending_calls.remove(call_key)
            && sender.send(result).is_err()
        {
            // No receivers, which is fine
            trace!(to = %call_key.to, "No receivers waiting for deduplicated call result");
        }
    }

    /// Clean up expired entries from all TTL caches.
    pub fn cleanup_expired(&self) {
        let start = Instant::now();
        let mut cleaned = 0;

        // Clean fee cache
        self.fee_cache.retain(|_, v| {
            let expired = v.is_expired();
            if expired {
                cleaned += 1;
            }
            !expired
        });

        // Clean code cache
        self.code_cache.retain(|_, v| {
            let expired = v.is_expired();
            if expired {
                cleaned += 1;
            }
            !expired
        });

        // Clean keys cache
        self.keys_cache.retain(|_, v| {
            let expired = v.is_expired();
            if expired {
                cleaned += 1;
            }
            !expired
        });

        // Clean fee history cache
        self.fee_history_cache.retain(|_, v| {
            let expired = v.is_expired();
            if expired {
                cleaned += 1;
            }
            !expired
        });

        if cleaned > 0 {
            debug!(
                cleaned = cleaned,
                duration_ms = start.elapsed().as_millis(),
                "Cleaned up expired cache entries"
            );
        }
    }

    /// Get cache statistics for monitoring.
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            chain_id_cached: self.chain_id.get().is_some(),
            delegation_impl_cached: self.delegation_impl.get().is_some(),
            fee_cache_size: self.fee_cache.len(),
            code_cache_size: self.code_cache.len(),
            keys_cache_size: self.keys_cache.len(),
            fee_history_cache_size: self.fee_history_cache.len(),
            pending_calls: self.pending_calls.len(),
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
    /// Whether delegation implementation is cached
    pub delegation_impl_cached: bool,
    /// Number of cached fee estimates
    pub fee_cache_size: usize,
    /// Number of cached contract codes
    pub code_cache_size: usize,
    /// Number of cached keys
    pub keys_cache_size: usize,
    /// Number of cached fee histories
    pub fee_history_cache_size: usize,
    /// Number of pending deduplicated calls
    pub pending_calls: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{address, bytes};
    use tokio::time::{Duration as TokioDuration, sleep};

    #[tokio::test]
    async fn test_static_caches() {
        let cache = RpcCache::new();

        // Test chain ID caching
        assert_eq!(cache.get_chain_id(), None);
        let chain_id = ChainId::from(1u64);
        cache.set_chain_id(chain_id);
        assert_eq!(cache.get_chain_id(), Some(chain_id));

        // Test delegation implementation caching
        assert_eq!(cache.get_delegation_impl(), None);
        let addr = address!("1234567890123456789012345678901234567890");
        cache.set_delegation_impl(addr);
        assert_eq!(cache.get_delegation_impl(), Some(addr));
    }

    #[tokio::test]
    async fn test_ttl_caches() {
        let cache = RpcCache::new();

        // Test fee estimate caching
        let key = "test_fee".to_string();
        let fee = U256::from(1000);

        assert_eq!(cache.get_fee_estimate(&key), None);
        cache.set_fee_estimate(key.clone(), fee);
        assert_eq!(cache.get_fee_estimate(&key), Some(fee));

        // Test code caching
        let addr = address!("1234567890123456789012345678901234567890");
        let code = bytes!("608060405234801561001057600080fd5b50");

        assert_eq!(cache.get_code(&addr), None);
        cache.set_code(addr, code.clone());
        assert_eq!(cache.get_code(&addr), Some(code));
    }

    #[tokio::test]
    async fn test_ttl_expiration() {
        let _cache = RpcCache::new();

        // Create a cached value with very short TTL
        let value = CachedValue::new("test", Duration::from_millis(10));
        assert_eq!(value.get_if_valid(), Some(&"test"));

        // Wait for expiration
        sleep(TokioDuration::from_millis(20)).await;
        assert_eq!(value.get_if_valid(), None);
        assert!(value.is_expired());
    }

    #[tokio::test]
    async fn test_call_deduplication() {
        let cache = RpcCache::new();

        let call_key = CallKey {
            to: address!("1234567890123456789012345678901234567890"),
            data: bytes!("a9059cbb"),
            block: "latest".to_string(),
        };

        // First call should return None (no existing call)
        assert!(cache.deduplicate_call(call_key.clone()).is_none());

        // Start deduplication
        let _sender = cache.start_call_deduplication(call_key.clone());

        // Second identical call should get a receiver
        let receiver = cache.deduplicate_call(call_key.clone());
        assert!(receiver.is_some());

        // Complete the call
        let result = Ok(bytes!("0000000000000000000000000000000000000000000000000000000000000001"));
        cache.complete_call_deduplication(&call_key, result.clone());

        // The receiver should get the result
        let mut receiver = receiver.unwrap();
        let received = receiver.recv().await.unwrap();
        assert_eq!(received, result);
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let cache = RpcCache::new();

        // Add some entries with short TTL
        let addr = address!("1234567890123456789012345678901234567890");
        let code = bytes!("608060405234801561001057600080fd5b50");

        // Manually insert expired entries
        cache.code_cache.insert(
            addr,
            CachedValue {
                value: code,
                cached_at: Instant::now() - Duration::from_secs(3600), // 1 hour ago
                ttl: Duration::from_secs(1800),                        // 30 minute TTL
            },
        );

        assert_eq!(cache.code_cache.len(), 1);

        // Cleanup should remove expired entries
        cache.cleanup_expired();
        assert_eq!(cache.code_cache.len(), 0);
    }

    #[test]
    fn test_cache_stats() {
        let cache = RpcCache::new();

        let stats = cache.stats();
        assert!(!stats.chain_id_cached);
        assert!(!stats.delegation_impl_cached);
        assert_eq!(stats.fee_cache_size, 0);
        assert_eq!(stats.code_cache_size, 0);
        assert_eq!(stats.keys_cache_size, 0);
        assert_eq!(stats.fee_history_cache_size, 0);
        assert_eq!(stats.pending_calls, 0);

        // Add some cached values
        cache.set_chain_id(ChainId::from(1u64));
        cache.set_fee_estimate("test".to_string(), U256::from(1000));

        let stats = cache.stats();
        assert!(stats.chain_id_cached);
        assert_eq!(stats.fee_cache_size, 1);
    }
}
