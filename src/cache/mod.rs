//! # Cache Module
//!
//! This module provides caching functionality to reduce redundant RPC calls and external API requests.
//! It reduces latency through intelligent caching strategies with appropriate TTLs.
//!
//! ## Components
//! - Generic cache infrastructure with TTL support
//! - Price oracle caching (60 second TTL)
//! - Delegation info caching (5 minute TTL)
//! - Token metadata caching (24 hour TTL)

pub mod delegation;
pub mod metrics;
pub mod price;
pub mod token;

use crate::error::RelayError;
use moka::future::Cache;
use std::{
    future::Future,
    hash::Hash,
    sync::Arc,
    time::Duration,
};

pub use delegation::{DelegationCache, DelegationInfo, DelegationKey};
pub use price::{PriceCache, PriceKey};
pub use token::{TokenCache, TokenKey, TokenMetadata};
pub use metrics::CacheMetrics;

/// Generic cache wrapper with TTL support and metrics
#[derive(Clone)]
pub struct RelayCache<K, V> {
    cache: Arc<Cache<K, V>>,
    name: &'static str,
    metrics: CacheMetrics,
}

impl<K, V> RelayCache<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Create a new cache with the specified configuration
    pub fn new(name: &'static str, max_capacity: u64, ttl: Duration) -> Self {
        let cache = Cache::builder()
            .max_capacity(max_capacity)
            .time_to_live(ttl)
            .build();

        Self {
            cache: Arc::new(cache),
            name,
            metrics: CacheMetrics::new(name),
        }
    }

    /// Get a value from the cache or fetch it if not present
    pub async fn get_or_fetch<F, Fut>(
        &self,
        key: K,
        fetcher: F,
    ) -> Result<V, RelayError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<V, RelayError>>,
    {
        // Check cache first
        if let Some(value) = self.cache.get(&key).await {
            self.metrics.record_hit();
            tracing::debug!(cache = self.name, "Cache hit");
            return Ok(value);
        }

        self.metrics.record_miss();
        tracing::debug!(cache = self.name, "Cache miss, fetching from source");

        // Fetch and cache
        let start = std::time::Instant::now();
        let value = fetcher().await?;
        let duration = start.elapsed();
        
        self.metrics.record_fetch_duration(duration);
        self.cache.insert(key.clone(), value.clone()).await;
        
        tracing::debug!(
            cache = self.name,
            duration_ms = duration.as_millis(),
            "Fetched and cached value"
        );

        Ok(value)
    }

    /// Invalidate a specific cache entry
    pub async fn invalidate(&self, key: &K) {
        self.cache.invalidate(key).await;
        self.metrics.record_invalidation();
        tracing::debug!(cache = self.name, "Cache entry invalidated");
    }

    /// Clear all cache entries
    pub async fn clear(&self) {
        let size_before = self.cache.entry_count();
        self.cache.invalidate_all();
        self.metrics.record_clear();
        tracing::info!(
            cache = self.name,
            entries_cleared = size_before,
            "Cache cleared"
        );
    }

    /// Get the current number of entries in the cache
    pub fn entry_count(&self) -> u64 {
        self.cache.entry_count()
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            name: self.name,
            entry_count: self.cache.entry_count(),
            metrics: self.metrics.get_stats(),
        }
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Cache name
    pub name: &'static str,
    /// Current number of entries
    pub entry_count: u64,
    /// Cache metrics
    pub metrics: metrics::MetricsSnapshot,
}

/// Cache type for selective clearing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheType {
    /// Price oracle cache
    Price,
    /// Delegation info cache
    Delegation,
    /// Token metadata cache
    Token,
    /// All caches
    All,
}