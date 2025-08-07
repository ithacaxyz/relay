# Phase 3: Caching Layer Implementation Plan

## Executive Summary

Phase 3 focuses on implementing a comprehensive caching layer to reduce redundant RPC calls and external API requests. This builds on Phase 1's parallel execution and Phase 2's multicall batching by caching frequently accessed data.

**Expected Impact**: 10-15% additional latency reduction, compounding to **60-70% total improvement** with Phases 1 & 2

## Caching Strategy

### What to Cache

1. **Price Oracle Data** (High Impact)
   - ETH/USD prices from CoinGecko
   - TTL: 30-60 seconds (prices don't change rapidly)
   - Benefit: Eliminate external API calls for same-block requests

2. **Delegation Implementation** (Medium Impact)
   - Contract implementation addresses
   - TTL: 5 minutes (rarely changes)
   - Benefit: Reduce eth_call operations

3. **ERC20 Metadata** (Low-Medium Impact)
   - Token name, symbol, decimals
   - TTL: Indefinite (immutable data)
   - Benefit: One-time fetch per token

4. **Account Keys & Orchestrator** (Medium Impact)
   - Account keys and orchestrator addresses
   - TTL: 1-2 minutes (changes infrequently)
   - Benefit: Reduce account queries

### What NOT to Cache

- **Balances**: Always need real-time values
- **Nonces**: Must be current for transaction submission
- **Gas Prices**: Need fresh values for accurate estimation
- **Simulation Results**: Too specific to cache effectively

## Implementation Architecture

### 1. Cache Infrastructure

```rust
// src/cache/mod.rs
pub mod price;
pub mod delegation;
pub mod token;
pub mod account;

use std::sync::Arc;
use moka::future::Cache;
use std::time::Duration;

/// Generic cache wrapper with TTL support
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
            return Ok(value);
        }
        
        self.metrics.record_miss();
        
        // Fetch and cache
        let value = fetcher().await?;
        self.cache.insert(key.clone(), value.clone()).await;
        
        Ok(value)
    }
    
    pub async fn invalidate(&self, key: &K) {
        self.cache.invalidate(key).await;
        self.metrics.record_invalidation();
    }
    
    pub async fn clear(&self) {
        self.cache.invalidate_all().await;
        self.metrics.record_clear();
    }
}
```

### 2. Price Cache Implementation

```rust
// src/cache/price.rs
use alloy::primitives::{Address, U256};
use std::time::Duration;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct PriceKey {
    pub token: Address,
    pub chain_id: ChainId,
    pub block_number: Option<u64>,
}

pub struct PriceCache {
    cache: RelayCache<PriceKey, U256>,
}

impl PriceCache {
    pub fn new() -> Self {
        Self {
            cache: RelayCache::new(
                "price_oracle",
                1000,  // Max 1000 entries
                Duration::from_secs(60),  // 60 second TTL
            ),
        }
    }
    
    pub async fn get_eth_price<F, Fut>(
        &self,
        token: Address,
        chain_id: ChainId,
        block_number: Option<u64>,
        fetcher: F,
    ) -> Result<U256, RelayError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<U256, RelayError>>,
    {
        let key = PriceKey {
            token,
            chain_id,
            block_number,
        };
        
        self.cache.get_or_fetch(key, fetcher).await
    }
}
```

### 3. Delegation Cache Implementation

```rust
// src/cache/delegation.rs
use alloy::primitives::Address;
use std::time::Duration;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct DelegationKey {
    pub account: Address,
    pub chain_id: ChainId,
}

#[derive(Debug, Clone)]
pub struct DelegationInfo {
    pub implementation: Address,
    pub orchestrator: Address,
    pub is_delegated: bool,
}

pub struct DelegationCache {
    cache: RelayCache<DelegationKey, DelegationInfo>,
}

impl DelegationCache {
    pub fn new() -> Self {
        Self {
            cache: RelayCache::new(
                "delegation",
                5000,  // Max 5000 entries
                Duration::from_secs(300),  // 5 minute TTL
            ),
        }
    }
    
    pub async fn get_delegation_info<F, Fut>(
        &self,
        account: Address,
        chain_id: ChainId,
        fetcher: F,
    ) -> Result<DelegationInfo, RelayError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<DelegationInfo, RelayError>>,
    {
        let key = DelegationKey { account, chain_id };
        self.cache.get_or_fetch(key, fetcher).await
    }
    
    pub async fn invalidate_account(&self, account: Address, chain_id: ChainId) {
        let key = DelegationKey { account, chain_id };
        self.cache.invalidate(&key).await;
    }
}
```

### 4. Token Metadata Cache

```rust
// src/cache/token.rs
use alloy::primitives::Address;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct TokenKey {
    pub address: Address,
    pub chain_id: ChainId,
}

#[derive(Debug, Clone)]
pub struct TokenMetadata {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
}

pub struct TokenCache {
    cache: RelayCache<TokenKey, TokenMetadata>,
}

impl TokenCache {
    pub fn new() -> Self {
        Self {
            cache: RelayCache::new(
                "token_metadata",
                10000,  // Max 10000 tokens
                Duration::from_secs(86400),  // 24 hour TTL (immutable data)
            ),
        }
    }
}
```

### 5. Integration with Relay

```rust
// src/rpc/relay.rs modifications

pub struct RelayInner {
    // ... existing fields ...
    
    // Phase 3: Add caches
    price_cache: Arc<PriceCache>,
    delegation_cache: Arc<DelegationCache>,
    token_cache: Arc<TokenCache>,
}

impl Relay {
    #[instrument(skip_all)]
    async fn estimate_fee(
        &self,
        intent: PartialIntent,
        chain_id: ChainId,
        prehash: bool,
        context: FeeEstimationContext,
    ) -> Result<(ChainAssetDiffs, Quote), RelayError> {
        // ... setup code ...
        
        // Phase 3: Use cached price oracle
        let eth_price = self.inner.price_cache
            .get_eth_price(
                token.address,
                chain_id,
                Some(block_number),
                || async {
                    self.inner.price_oracle.eth_price(token.kind).await
                },
            )
            .await?;
        
        // Phase 3: Use cached delegation info
        let delegation_info = self.inner.delegation_cache
            .get_delegation_info(
                intent.eoa,
                chain_id,
                || async {
                    // Fetch using Phase 2 multicall
                    let multicall = MulticallBatcher::new(provider.clone());
                    let results = multicall
                        .batch_account_queries(intent.eoa, delegation_addr)
                        .await?;
                    
                    Ok(DelegationInfo {
                        implementation: results.implementation,
                        orchestrator: results.orchestrator,
                        is_delegated: results.is_delegated,
                    })
                },
            )
            .await?;
            
        // ... rest of the function ...
    }
}
```

## Cache Invalidation Strategy

### 1. Time-Based Invalidation (Primary)
- Automatic TTL expiration
- Different TTLs for different data types
- Configurable via environment variables

### 2. Event-Based Invalidation
```rust
// Invalidate on transaction completion
async fn on_transaction_confirmed(&self, tx: &TransactionReceipt) {
    if let Some(account) = tx.from {
        self.delegation_cache.invalidate_account(account, tx.chain_id).await;
    }
}
```

### 3. Manual Invalidation
```rust
// Admin endpoint for cache clearing
async fn clear_cache(&self, cache_type: CacheType) -> Result<(), RelayError> {
    match cache_type {
        CacheType::Price => self.price_cache.clear().await,
        CacheType::Delegation => self.delegation_cache.clear().await,
        CacheType::Token => self.token_cache.clear().await,
        CacheType::All => {
            self.price_cache.clear().await;
            self.delegation_cache.clear().await;
            self.token_cache.clear().await;
        }
    }
    Ok(())
}
```

## Configuration

```yaml
# relay.yaml
cache:
  enabled: true
  price:
    ttl_seconds: 60
    max_entries: 1000
  delegation:
    ttl_seconds: 300
    max_entries: 5000
  token:
    ttl_seconds: 86400
    max_entries: 10000
```

## Metrics & Monitoring

```rust
// src/cache/metrics.rs
use prometheus::{Counter, Histogram, register_counter, register_histogram};

pub struct CacheMetrics {
    hits: Counter,
    misses: Counter,
    invalidations: Counter,
    fetch_duration: Histogram,
}

impl CacheMetrics {
    pub fn new(cache_name: &str) -> Self {
        Self {
            hits: register_counter!(
                format!("relay_cache_{}_hits_total", cache_name),
                format!("Total cache hits for {}", cache_name)
            ).unwrap(),
            misses: register_counter!(
                format!("relay_cache_{}_misses_total", cache_name),
                format!("Total cache misses for {}", cache_name)
            ).unwrap(),
            invalidations: register_counter!(
                format!("relay_cache_{}_invalidations_total", cache_name),
                format!("Total cache invalidations for {}", cache_name)
            ).unwrap(),
            fetch_duration: register_histogram!(
                format!("relay_cache_{}_fetch_duration_seconds", cache_name),
                format!("Duration of cache fetches for {}", cache_name)
            ).unwrap(),
        }
    }
}
```

## Success Metrics

| Metric | Before Phase 3 | After Phase 3 | Target |
|--------|----------------|---------------|--------|
| Cache hit rate | 0% | >60% | 70% |
| External API calls | 100% | <40% | 30% |
| p50 latency | ~7ms¹ | ~6ms | 5ms |
| p99 latency | ~14ms¹ | ~12ms | 10ms |

¹ *After Phase 1 & 2 improvements*

## Risk Mitigation

### 1. Stale Data
- **Risk**: Serving outdated prices or delegation info
- **Mitigation**: Conservative TTLs, event-based invalidation

### 2. Memory Usage
- **Risk**: Unbounded cache growth
- **Mitigation**: Max capacity limits, LRU eviction

### 3. Cache Stampede
- **Risk**: Many concurrent requests for expired data
- **Mitigation**: Lock-based single flight fetching

## Implementation Timeline

### Week 1: Core Infrastructure
- [ ] Implement generic RelayCache wrapper
- [ ] Add cache metrics infrastructure
- [ ] Create configuration system

### Week 2: Specific Caches
- [ ] Implement PriceCache
- [ ] Implement DelegationCache
- [ ] Implement TokenCache

### Week 3: Integration
- [ ] Integrate caches into estimate_fee
- [ ] Add invalidation hooks
- [ ] Add admin endpoints

### Week 4: Testing & Optimization
- [ ] Load testing with caches
- [ ] TTL tuning based on metrics
- [ ] Documentation updates

## Dependencies

```toml
# Cargo.toml additions
moka = { version = "0.12", features = ["future"] }
dashmap = "5.5"
```

## Next Steps

1. Implement core cache infrastructure
2. Add specific cache implementations
3. Integrate with existing relay functions
4. Add comprehensive metrics
5. Test and tune cache parameters
6. Document cache behavior and configuration