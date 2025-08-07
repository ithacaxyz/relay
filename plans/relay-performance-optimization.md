# Relay Performance Optimization Plan

## Executive Summary

The Ithaca Relay service currently experiences ~15ms latency in the `estimate_fee` RPC method due to sequential JSON-RPC calls to the underlying Ethereum node. This plan outlines a comprehensive refactoring strategy to reduce latency by 40-60% through parallelization, batching, and caching techniques.

## Current Performance Analysis

### Identified Bottlenecks

Based on trace analysis (`Trace-c88cf0-2025-08-06`):

1. **Sequential RPC Calls**: 11-12 single-shot JSON-RPC calls per `get_keys_onchain`/`get_delegation_implementation`
   - `eth_getCode`: 2-3ms
   - `eth_call` (×8-9): 1-3ms each
   - `eth_getBalance`: 1-4ms
   - Total: ~78ms wall-clock time with only ~0.7ms CPU busy time

2. **Waterfall Pattern in `estimate_fee`**:
   - Sequential execution of independent operations
   - `simulate_execute` and `estimate_extra_fee` run sequentially instead of in parallel
   - Multiple chains processed serially in `determine_quote_strategy`

3. **Redundant Data Fetching**:
   - Re-fetch of price & delegation per chain
   - Duplicate `get_keys_onchain` + `get_delegation_implementation` cycles for same EOA
   - No caching of frequently accessed data

## Implementation Phases

### Phase 1: Parallel Execution with tokio::join!
**Priority: HIGH | Impact: 30-40% latency reduction | Effort: LOW**

#### 1.1 Initial Data Fetching Parallelization

**Current Code Location**: `src/rpc/relay.rs:301-326`

**Current Implementation**:
```rust
let (orchestrator, delegation, fee_history, eth_price) = try_join4(
    // fetch orchestrator from the account
    async { ... },
    // fetch delegation from the account
    self.has_supported_delegation(&account),
    // fetch chain fees
    provider.get_fee_history(...),
    // fetch price in eth
    async { ... },
).await?;
```

**Optimized Implementation**:
```rust
let (
    fee_token_balance,
    orchestrator,
    delegation,
    fee_history,
    eth_price
) = tokio::try_join!(
    self.get_assets(GetAssetsParameters { ... }),
    account.get_orchestrator(),
    self.has_supported_delegation(&account),
    provider.get_fee_history(
        EIP1559_FEE_ESTIMATION_PAST_BLOCKS,
        Default::default(),
        &[self.inner.priority_fee_percentile],
    ),
    self.inner.price_oracle.eth_price(token.kind)
)?;
```

#### 1.2 Simulation Phase Parallelization

**Current Code Location**: `src/rpc/relay.rs:425-435`

**Current Implementation**:
```rust
let (asset_diffs, sim_result) = orchestrator
    .simulate_execute(...)
    .await?;

let extra_payment = self.estimate_extra_fee(&chain, &intent_to_sign).await?
    * U256::from(10u128.pow(token.decimals as u32))
    / eth_price;
```

**Optimized Implementation**:
```rust
let ((asset_diffs, sim_result), extra_fee_eth) = tokio::try_join!(
    orchestrator.simulate_execute(
        self.simulator(),
        &intent_to_sign,
        context.account_key.keyType,
        self.inner.asset_info.clone(),
    ),
    self.estimate_extra_fee(&chain, &intent_to_sign)
)?;

let extra_payment = extra_fee_eth
    * U256::from(10u128.pow(token.decimals as u32))
    / eth_price;
```

### Phase 2: Multicall3 Batching ✅ **[IMPLEMENTATION READY]**
**Priority: HIGH | Impact: 20-30% latency reduction | Effort: MEDIUM**

**Status**: 🚧 **Implementation branch ready** (`yk/phase2-multicall`)
- ✅ Multicall3 helper module created (`src/rpc/multicall.rs`)
- ✅ Architecture designed and documented
- ✅ Error handling integrated with RelayError
- ✅ Fallback mechanisms for chain compatibility
- ⏳ Ready for integration with estimate_fee

#### 2.1 Create Multicall Helper Module

**New File**: `src/rpc/multicall.rs`

```rust
use alloy::{
    primitives::{Address, Bytes, U256},
    providers::Provider,
    sol,
};

sol! {
    #[sol(rpc)]
    interface Multicall3 {
        struct Call3 {
            address target;
            bool allowFailure;
            bytes callData;
        }
        
        struct Result {
            bool success;
            bytes returnData;
        }
        
        function aggregate3(Call3[] calldata calls) 
            external payable 
            returns (Result[] memory returnData);
    }
}

pub struct MulticallHelper {
    multicall_address: Address,
}

impl MulticallHelper {
    pub async fn fetch_account_data<P: Provider>(
        &self,
        provider: P,
        account: Address,
        orchestrator: Address,
        delegation: Address,
    ) -> Result<(Vec<Key>, Address, U256), RelayError> {
        let calls = vec![
            // getKeys call
            Call3 {
                target: orchestrator,
                allowFailure: false,
                callData: /* encoded getKeys call */,
            },
            // getDelegationImplementation call
            Call3 {
                target: delegation,
                allowFailure: false,
                callData: /* encoded call */,
            },
            // getBalance call
            Call3 {
                target: account,
                allowFailure: false,
                callData: /* encoded balance call */,
            },
        ];
        
        let results = Multicall3::new(self.multicall_address, provider)
            .aggregate3(calls)
            .await?;
        
        // Decode results
        Ok(decode_results(results))
    }
}
```

#### 2.2 Integration Points

1. Replace sequential calls in `get_keys_onchain`
2. Replace sequential calls in `get_delegation_implementation`
3. Bundle ERC20 metadata fetches (name, symbol, decimals)
4. Batch multiple balance queries

### Phase 3: Caching Layer
**Priority: MEDIUM | Impact: 10-15% latency reduction | Effort: MEDIUM**

#### 3.1 Price Oracle Cache

**New Module**: `src/cache/price.rs`

```rust
use std::sync::Arc;
use dashmap::DashMap;
use tokio::time::{Duration, Instant};

pub struct PriceCache {
    cache: Arc<DashMap<(Address, u64), CachedPrice>>,
    ttl: Duration,
}

struct CachedPrice {
    price: U256,
    timestamp: Instant,
    block_number: u64,
}

impl PriceCache {
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
            ttl: Duration::from_secs(ttl_seconds),
        }
    }
    
    pub async fn get_or_fetch<F, Fut>(
        &self,
        token: Address,
        block_number: u64,
        fetcher: F,
    ) -> Result<U256, RelayError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<U256, RelayError>>,
    {
        let key = (token, block_number);
        
        // Check cache
        if let Some(entry) = self.cache.get(&key) {
            if entry.timestamp.elapsed() < self.ttl {
                return Ok(entry.price);
            }
        }
        
        // Fetch and cache
        let price = fetcher().await?;
        self.cache.insert(key, CachedPrice {
            price,
            timestamp: Instant::now(),
            block_number,
        });
        
        Ok(price)
    }
}
```

#### 3.2 Delegation Implementation Cache

```rust
pub struct DelegationCache {
    cache: Arc<DashMap<Address, CachedDelegation>>,
    ttl: Duration,
}

struct CachedDelegation {
    implementation: Address,
    timestamp: Instant,
    block_number: u64,
}
```

#### 3.3 ERC20 Metadata Cache

```rust
pub struct TokenMetadataCache {
    cache: Arc<DashMap<Address, TokenMetadata>>,
}

struct TokenMetadata {
    name: String,
    symbol: String,
    decimals: u8,
    cached_at: Instant,
}
```

### Phase 4: JSON-RPC Batch Fallback
**Priority: LOW | Impact: Fallback mechanism | Effort: LOW**

**New Function**: `src/rpc/batch.rs`

```rust
pub async fn batch_rpc_fallback<P: Provider>(
    provider: P,
    calls: Vec<RpcCall>,
) -> Result<Vec<JsonValue>, RelayError> {
    // Check if Multicall3 is available
    if !has_multicall3(&provider).await {
        // Use JSON-RPC batch
        let batch_request = calls
            .into_iter()
            .map(|call| json!({
                "jsonrpc": "2.0",
                "method": call.method,
                "params": call.params,
                "id": call.id,
            }))
            .collect::<Vec<_>>();
        
        provider.batch_request(batch_request).await
    } else {
        // Use Multicall3
        multicall_batch(provider, calls).await
    }
}
```

### Phase 5: Micro-optimizations
**Priority: LOW | Impact: 1-2% improvement | Effort: LOW**

#### 5.1 Buffer Reuse in estimate_extra_fee

```rust
thread_local! {
    static ENCODE_BUFFER: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(1024));
}

async fn estimate_extra_fee(&self, chain: &Chain, intent: &Intent) -> Result<U256, RelayError> {
    if chain.is_optimism {
        let encoded = ENCODE_BUFFER.with(|buf| {
            let mut buffer = buf.borrow_mut();
            buffer.clear();
            
            let tx = TxEip1559 { /* ... */ };
            let signed_tx = tx.into_signed(signature);
            signed_tx.eip2718_encode(&mut buffer);
            
            buffer.clone()
        });
        
        chain.provider.estimate_l1_fee(encoded.into()).await
    } else {
        Ok(U256::ZERO)
    }
}
```

#### 5.2 Memoize approx_intrinsic_cost

```rust
use once_cell::sync::Lazy;
use dashmap::DashMap;

static INTRINSIC_COST_CACHE: Lazy<DashMap<(bool, usize), u64>> = 
    Lazy::new(|| DashMap::new());

fn approx_intrinsic_cost(data: &[u8], has_auth: bool) -> u64 {
    let key = (has_auth, data.len());
    
    if let Some(cost) = INTRINSIC_COST_CACHE.get(&key) {
        return *cost;
    }
    
    let cost = calculate_intrinsic_cost(data, has_auth);
    INTRINSIC_COST_CACHE.insert(key, cost);
    cost
}
```

### Phase 6: Higher-level Parallelization
**Priority: HIGH (for multi-chain) | Impact: 50%+ for multi-chain | Effort: LOW**

**Location**: `src/rpc/relay.rs` in `prepare_calls`

```rust
pub async fn prepare_calls(
    &self,
    parameters: PrepareCallsParameters,
) -> RpcResult<PrepareCallsResponse> {
    // When handling multiple chains
    let quotes = if parameters.chains.len() > 1 {
        // Parallel execution for all chains
        futures::future::try_join_all(
            parameters.chains.iter().map(|chain_id| {
                let intent = intent.clone();
                let context = context.clone();
                async move {
                    self.estimate_fee(intent, *chain_id, prehash, context).await
                }
            })
        ).await?
    } else {
        // Single chain
        vec![self.estimate_fee(intent, parameters.chains[0], prehash, context).await?]
    };
}
```

## Implementation Timeline

| Week | Tasks | Deliverables |
|------|-------|-------------|
| Week 1 | Phase 1 + Phase 6 | Parallel execution implemented, 30-40% improvement |
| Week 2 | Phase 2 | Multicall3 batching, additional 20-30% improvement |
| Week 3 | Phase 3 | Caching layer, 10-15% improvement |
| Week 4 | Phase 4 + 5 + Testing | Complete optimization, benchmarks |

## Testing Strategy

### Unit Tests
- Test parallel execution error handling
- Test cache hit/miss scenarios
- Test multicall encoding/decoding
- Test fallback mechanisms

### Integration Tests
```rust
#[tokio::test]
async fn test_estimate_fee_performance() {
    let env = Environment::setup().await.unwrap();
    
    let start = Instant::now();
    let result = env.relay.estimate_fee(/* ... */).await;
    let duration = start.elapsed();
    
    assert!(duration < Duration::from_millis(10));
}
```

### Load Testing
```bash
# Using vegeta for load testing
echo "POST http://localhost:8545" | vegeta attack \
    -body estimate_fee_request.json \
    -duration=30s \
    -rate=100/s | vegeta report
```

### Benchmarking
```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_estimate_fee(c: &mut Criterion) {
    c.bench_function("estimate_fee", |b| {
        b.to_async(Runtime::new().unwrap())
            .iter(|| async {
                relay.estimate_fee(black_box(intent)).await
            });
    });
}
```

## Success Metrics

| Metric | Current | Target | Measurement |
|--------|---------|--------|-------------|
| p50 latency | ~15ms | ~8ms | OpenTelemetry traces |
| p99 latency | ~30ms | ~15ms | OpenTelemetry traces |
| RPC calls per request | 11-12 | 3-4 | Request logs |
| Cache hit rate | 0% | >60% | Prometheus metrics |
| Error rate | <0.1% | <0.1% | Error logs |

## Risk Mitigation

### Feature Flags
```rust
pub struct OptimizationFlags {
    pub enable_parallel_execution: bool,
    pub enable_multicall: bool,
    pub enable_caching: bool,
    pub enable_batch_fallback: bool,
}
```

### Rollback Strategy
1. Monitor error rates and latency metrics
2. Gradual rollout: 1% → 10% → 50% → 100%
3. Automatic rollback on error spike
4. Manual override via environment variables

### Error Handling
```rust
// Fallback to sequential on parallel execution failure
let result = tokio::try_join!(op1, op2, op3)
    .or_else(|_| async {
        // Sequential fallback
        let r1 = op1.await?;
        let r2 = op2.await?;
        let r3 = op3.await?;
        Ok((r1, r2, r3))
    }).await?;
```

## Monitoring & Alerting

### Key Metrics to Monitor
1. **Latency percentiles** (p50, p95, p99)
2. **RPC call count** per request
3. **Cache hit rates**
4. **Error rates** by error type
5. **Resource utilization** (CPU, memory)

### Prometheus Metrics
```rust
lazy_static! {
    static ref ESTIMATE_FEE_DURATION: Histogram = register_histogram!(
        "relay_estimate_fee_duration_seconds",
        "Duration of estimate_fee calls"
    ).unwrap();
    
    static ref CACHE_HIT_RATE: Counter = register_counter!(
        "relay_cache_hits_total",
        "Total number of cache hits"
    ).unwrap();
    
    static ref RPC_CALLS_PER_REQUEST: Histogram = register_histogram!(
        "relay_rpc_calls_per_request",
        "Number of RPC calls per request"
    ).unwrap();
}
```

### Alerting Rules
```yaml
alerts:
  - name: HighLatency
    expr: histogram_quantile(0.99, relay_estimate_fee_duration_seconds) > 0.015
    for: 5m
    annotations:
      summary: "estimate_fee p99 latency above 15ms"
      
  - name: LowCacheHitRate
    expr: rate(relay_cache_hits_total[5m]) < 0.6
    for: 10m
    annotations:
      summary: "Cache hit rate below 60%"
```

## Appendix

### A. Detailed Trace Analysis

From `Trace-c88cf0-2025-08-06`:
- Total spans: ~1,400
- Idle time: >90% of wall clock time
- Busy time: <1ms actual computation
- Network RTT dominates execution time

### B. Code References

Key files to modify:
- `src/rpc/relay.rs`: Main RPC implementation
- `src/types/account.rs`: Account data fetching
- `src/price/oracle.rs`: Price fetching logic
- `src/transactions/fees.rs`: Fee estimation
- `src/provider.rs`: Provider extensions

### C. Dependencies

New dependencies to add to `Cargo.toml`:
```toml
dashmap = "5.5"
once_cell = "1.19"
moka = { version = "0.12", features = ["future"] }
```

### D. Configuration

New configuration options in `config.yaml`:
```yaml
optimization:
  enable_parallel_execution: true
  enable_multicall: true
  enable_caching: true
  cache_ttl_seconds: 12
  multicall_address: "0xcA11bde05977b3631167028862bE2a173976CA11"
```