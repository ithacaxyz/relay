# Multicall3 Batching Implementation Plan

## Overview
Implement Multicall3 batching using Alloy's native support to reduce RPC calls from 8-12 to 1-3 per request (3-4x performance improvement).

## Phase 1: Provider Extension (Day 1)

### Add Multicall Extension Trait
**File**: `src/provider.rs`

```rust
use alloy::contract::Multicall;

pub trait MulticallExt: Provider {
    /// Check if chain supports Multicall3
    async fn supports_multicall(&self) -> bool {
        const MULTICALL3_ADDRESS: Address = address!("cA11bde05977b3631167028862bE2a173976CA11");
        !self.get_code_at(MULTICALL3_ADDRESS).await?.is_empty()
    }
    
    /// Create a multicall instance with automatic fallback
    fn batch_calls(&self) -> Multicall<Self> {
        self.contract(MULTICALL3_ADDRESS)
            .aggregate3()
            .allow_failure(false)
    }
}
```

## Phase 2: Optimize estimate_fee (Day 2-3)

### Batch Account Queries
**File**: `src/rpc/relay.rs` (lines 353-366)

Replace sequential calls with batched multicall:

```rust
// Before: 2 separate async calls with try_join
// After: Single multicall batch
let batch = provider.batch_calls()
    .add_call(account.get_orchestrator())
    .add_call(account.delegation_implementation())
    .execute().await?;
```

### Batch Key Queries  
**File**: `src/rpc/relay.rs` (get_keys_onchain method)

```rust
async fn get_keys_onchain_batched(&self, accounts: Vec<Address>) -> Result<HashMap<Address, Vec<Key>>> {
    let mut multicall = provider.batch_calls();
    
    for account in &accounts {
        multicall = multicall
            .add(Account::new(*account).is_delegated())
            .add(Account::new(*account).keys());
    }
    
    let results = multicall.execute().await?;
    // Parse results into HashMap
}
```

## Phase 3: Multi-Account Batching (Day 4)

### Batch Multiple Account States
**File**: `src/rpc/relay.rs`

```rust
async fn get_account_states_batch(&self, accounts: &[Address]) -> Vec<AccountState> {
    let batch = provider.batch_calls();
    
    // Add all orchestrator calls
    for account in accounts {
        batch.add(IthacaAccount::new(account).ORCHESTRATOR());
    }
    
    // Add all delegation calls  
    for account in accounts {
        batch.add(DelegationProxy::new(account).implementation());
    }
    
    let results = batch.execute().await?;
    parse_account_states(accounts, results)
}
```

## Phase 4: Asset Query Optimization (Day 5)

### Batch Balance Queries
**File**: `src/rpc/relay.rs` (lines 1563-1648)

```rust
async fn get_assets_optimized(&self, request: GetAssetsParameters) -> GetAssetsResponse {
    // Group by chain for efficient multicall
    let mut chain_batches = HashMap::new();
    
    for (chain_id, assets) in request.asset_filter {
        let batch = self.provider(chain_id)?.batch_calls();
        
        for asset in assets {
            if asset.is_native() {
                batch.add_eth_balance(request.account);
            } else {
                batch.add(IERC20::new(asset.address).balanceOf(request.account));
            }
        }
        
        chain_batches.insert(chain_id, batch);
    }
    
    // Execute all batches in parallel
    let results = try_join_all(chain_batches.into_iter().map(|(chain, batch)| 
        async move { (chain, batch.execute().await) }
    )).await?;
}
```

## Phase 5: Integration with RpcCache (Day 6)

### Cache-Aware Multicall
**File**: `src/cache/mod.rs`

```rust
impl RpcCache {
    /// Get cached values and prepare batch for uncached items
    pub fn prepare_multicall_batch<T>(&self, keys: Vec<CacheKey>) -> (Vec<Option<T>>, Vec<Call>) {
        let mut cached = Vec::new();
        let mut calls = Vec::new();
        
        for key in keys {
            if let Some(value) = self.get(&key) {
                cached.push(Some(value));
            } else {
                cached.push(None);
                calls.push(key.to_call());
            }
        }
        
        (cached, calls)
    }
    
    /// Merge cached and fetched results
    pub fn merge_results<T>(&self, cached: Vec<Option<T>>, fetched: Vec<T>) -> Vec<T> {
        let mut fetched_iter = fetched.into_iter();
        cached.into_iter().map(|opt| 
            opt.unwrap_or_else(|| fetched_iter.next().unwrap())
        ).collect()
    }
}
```

## Phase 6: Metrics & Monitoring (Day 7)

### Add Multicall Metrics
**File**: `src/metrics/mod.rs`

```rust
lazy_static! {
    static ref MULTICALL_BATCH_SIZE: Histogram = register_histogram!(
        "relay_multicall_batch_size",
        "Size of multicall batches"
    ).unwrap();
    
    static ref MULTICALL_SAVINGS: Counter = register_counter!(
        "relay_multicall_rpc_calls_saved",
        "Number of RPC calls saved by batching"
    ).unwrap();
    
    static ref MULTICALL_FALLBACK: Counter = register_counter!(
        "relay_multicall_fallback_count",
        "Number of times fallback to sequential calls was used"
    ).unwrap();
}
```

## Testing Strategy

### Unit Tests
```rust
#[tokio::test]
async fn test_multicall_performance() {
    let env = Environment::setup().await.unwrap();
    
    // Measure sequential vs batched
    let start = Instant::now();
    let sequential = get_accounts_sequential(&accounts).await;
    let seq_time = start.elapsed();
    
    let start = Instant::now();
    let batched = get_accounts_batched(&accounts).await;
    let batch_time = start.elapsed();
    
    assert!(batch_time < seq_time / 3);
    assert_eq!(sequential, batched);
}
```

### Integration Tests
- Test chains without Multicall3 support
- Test partial failures with tryAggregate
- Test cache integration
- Test cross-chain operations

## Implementation Checklist

- [ ] **Phase 1**: Provider extension trait
- [ ] **Phase 2**: Optimize estimate_fee method
- [ ] **Phase 3**: Multi-account batching
- [ ] **Phase 4**: Asset query optimization  
- [ ] **Phase 5**: Cache integration
- [ ] **Phase 6**: Metrics and monitoring
- [ ] **Testing**: Unit and integration tests
- [ ] **Benchmarks**: Performance validation
- [ ] **Documentation**: Update API docs

## Success Metrics

| Metric | Current | Target |
|--------|---------|--------|
| RPC calls per request | 8-12 | 1-3 |
| p50 latency | baseline | -60% |
| p99 latency | baseline | -40% |
| Cache hit rate | N/A | >80% |
| Fallback rate | N/A | <5% |

## Risk Mitigation

1. **Graceful Degradation**: Automatic fallback to sequential calls
2. **Circuit Breaker**: Disable multicall per-chain if failures exceed threshold
3. **Monitoring**: Alert on performance regression or high fallback rate
4. **Rollback Plan**: Feature flag to disable multicall globally

## Next Steps

1. Switch to worktree: `cd worktree/multicall3`
2. Create feature branch from main
3. Implement Phase 1 (Provider Extension)
4. Benchmark baseline performance
5. Proceed with incremental implementation