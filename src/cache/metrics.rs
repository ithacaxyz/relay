//! Cache metrics for monitoring and observability

use metrics::{counter, histogram};
use std::time::Duration;

/// Cache metrics collector
#[derive(Clone)]
pub struct CacheMetrics {
    cache_name: &'static str,
}

impl CacheMetrics {
    /// Create a new metrics collector for a cache
    pub fn new(cache_name: &'static str) -> Self {
        Self { cache_name }
    }

    /// Record a cache hit
    pub fn record_hit(&self) {
        counter!(
            "relay_cache_hits_total",
            "cache" => self.cache_name
        ).increment(1);
    }

    /// Record a cache miss
    pub fn record_miss(&self) {
        counter!(
            "relay_cache_misses_total",
            "cache" => self.cache_name
        ).increment(1);
    }

    /// Record a cache invalidation
    pub fn record_invalidation(&self) {
        counter!(
            "relay_cache_invalidations_total",
            "cache" => self.cache_name
        ).increment(1);
    }

    /// Record a cache clear operation
    pub fn record_clear(&self) {
        counter!(
            "relay_cache_clears_total",
            "cache" => self.cache_name
        ).increment(1);
    }

    /// Record the duration of a fetch operation
    pub fn record_fetch_duration(&self, duration: Duration) {
        histogram!(
            "relay_cache_fetch_duration_seconds",
            "cache" => self.cache_name
        ).record(duration.as_secs_f64());
    }

    /// Get current metrics snapshot
    pub fn get_stats(&self) -> MetricsSnapshot {
        // In a real implementation, this would query the metrics backend
        // For now, return a placeholder
        MetricsSnapshot::default()
    }
}

/// Snapshot of cache metrics at a point in time
#[derive(Debug, Clone, Default)]
pub struct MetricsSnapshot {
    /// Total cache hits
    pub hits: u64,
    /// Total cache misses
    pub misses: u64,
    /// Total invalidations
    pub invalidations: u64,
    /// Total clear operations
    pub clears: u64,
    /// Hit rate percentage
    pub hit_rate: f64,
}

impl MetricsSnapshot {
    /// Calculate hit rate from hits and misses
    pub fn calculate_hit_rate(hits: u64, misses: u64) -> f64 {
        let total = hits + misses;
        if total == 0 {
            0.0
        } else {
            (hits as f64 / total as f64) * 100.0
        }
    }
}