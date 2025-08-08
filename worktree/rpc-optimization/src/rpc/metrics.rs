use metrics::{Counter, Histogram};
use metrics_derive::Metrics;

/// Metrics for delegation cache operations.
#[derive(Metrics, Clone)]
#[metrics(scope = "relay.delegation_cache")]
pub struct DelegationCacheMetrics {
    /// Number of cache hits
    pub hits: Counter,
    /// Number of cache misses
    pub misses: Counter,
    /// Number of cache errors
    pub errors: Counter,
    /// Number of cache invalidations
    pub invalidations: Counter,
    /// Duration of cache lookups in nanoseconds
    pub lookup_duration: Histogram,
    /// Duration of RPC calls when cache misses in nanoseconds  
    pub rpc_duration: Histogram,
}