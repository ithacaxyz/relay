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
use tracing::{debug, trace, warn};

/// Thread-safe cache for RPC results with TTL support and request deduplication.
#[derive(Debug)]
pub struct RpcCache {
    /// Static cache for chain ID (never expires)
    chain_id: OnceLock<ChainId>,
    /// TTL cache for fee estimates
    fee_cache: DashMap<String, CachedValue<U256>>,
    /// TTL cache for contract code
    code_cache: DashMap<Address, CachedValue<Bytes>>,
    /// TTL cache for account keys
    /// TTL cache for fee history data
    fee_history_cache: DashMap<String, CachedValue<serde_json::Value>>,
    /// Request deduplication for eth_call
    pending_calls: DashMap<CallKey, PendingCall>,
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

/// A pending call with timestamp tracking for timeout cleanup.
#[derive(Debug)]
struct PendingCall {
    sender: Arc<broadcast::Sender<CallResult>>,
    started_at: Instant,
}

/// Result of attempting to deduplicate a call.
#[derive(Debug)]
pub enum DeduplicationResult {
    /// An existing call is in progress, wait for its result.
    Existing(broadcast::Receiver<CallResult>),
    /// No existing call, caller should proceed and broadcast the result.
    New(Arc<broadcast::Sender<CallResult>>),
}

impl RpcCache {
    /// Create a new RPC cache instance.
    pub fn new() -> Self {
        Self {
            chain_id: OnceLock::new(),
            fee_cache: DashMap::new(),
            code_cache: DashMap::new(),
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

    /// Atomically check for an existing call or start a new one.
    /// Returns either an existing receiver to wait for results, or a sender to broadcast results.
    pub fn deduplicate_call(
        &self,
        call_key: CallKey,
    ) -> DeduplicationResult {
        use dashmap::mapref::entry::Entry;
        
        let (tx, _) = broadcast::channel(1);
        let tx = Arc::new(tx);
        
        match self.pending_calls.entry(call_key.clone()) {
            Entry::Occupied(entry) => {
                debug!(to = %call_key.to, "Call deduplication HIT - waiting for existing call");
                DeduplicationResult::Existing(entry.get().sender.subscribe())
            }
            Entry::Vacant(entry) => {
                debug!(to = %call_key.to, "Call deduplication MISS - starting new call");
                entry.insert(PendingCall {
                    sender: tx.clone(),
                    started_at: Instant::now(),
                });
                DeduplicationResult::New(tx)
            }
        }
    }

    /// Complete a call deduplication by broadcasting the result and cleaning up.
    pub fn complete_call_deduplication(&self, call_key: &CallKey, result: CallResult) {
        if let Some((_, pending_call)) = self.pending_calls.remove(call_key)
            && pending_call.sender.send(result).is_err()
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

        // Clean fee history cache
        self.fee_history_cache.retain(|_, v| {
            let expired = v.is_expired();
            if expired {
                cleaned += 1;
            }
            !expired
        });

        // Clean up stale pending calls (no receivers or timed out after 30 seconds)
        const PENDING_CALL_TIMEOUT: Duration = Duration::from_secs(30);
        self.pending_calls.retain(|call_key, pending_call| {
            let timed_out = pending_call.started_at.elapsed() > PENDING_CALL_TIMEOUT;
            let no_receivers = pending_call.sender.receiver_count() == 0;
            
            if timed_out || no_receivers {
                if timed_out {
                    warn!(
                        to = %call_key.to,
                        elapsed_secs = pending_call.started_at.elapsed().as_secs(),
                        "Removing timed out pending call"
                    );
                }
                cleaned += 1;
                false // Remove this entry
            } else {
                true // Keep this entry
            }
        });

        if cleaned > 0 {
            debug!(
                cleaned = cleaned,
                pending_calls = self.pending_calls.len(),
                duration_ms = start.elapsed().as_millis(),
                "Cleaned up expired cache entries"
            );
        }
    }

    /// Get cache statistics for monitoring.
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            chain_id_cached: self.chain_id.get().is_some(),
            fee_cache_size: self.fee_cache.len(),
            code_cache_size: self.code_cache.len(),
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
    /// Number of cached fee estimates
    pub fee_cache_size: usize,
    /// Number of cached contract codes
    pub code_cache_size: usize,
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

        // First call should return New (no existing call)
        let _sender = match cache.deduplicate_call(call_key.clone()) {
            DeduplicationResult::New(sender) => sender,
            DeduplicationResult::Existing(_) => panic!("Expected New, got Existing"),
        };

        // Second identical call should get a receiver
        let mut receiver = match cache.deduplicate_call(call_key.clone()) {
            DeduplicationResult::Existing(receiver) => receiver,
            DeduplicationResult::New(_) => panic!("Expected Existing, got New"),
        };

        // Complete the call
        let result = Ok(bytes!("0000000000000000000000000000000000000000000000000000000000000001"));
        cache.complete_call_deduplication(&call_key, result.clone());

        // The receiver should get the result
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
        assert_eq!(stats.fee_cache_size, 0);
        assert_eq!(stats.code_cache_size, 0);
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
