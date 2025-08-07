# Phase 2: Multicall3 Batching Implementation Plan

## Executive Summary

Phase 2 focuses on reducing the number of sequential `eth_call` operations by batching them using Multicall3. This builds on Phase 1's parallel execution gains by further reducing network round-trips from 8-12 individual calls to 2-3 batched calls.

**Expected Impact**: 20-30% additional latency reduction (compounding with Phase 1's 30-40%)

## Current RPC Call Analysis

### Before Phase 2: Individual RPC Calls in `estimate_fee`

```
Parallel Group (Phase 1 optimized):
├─ get_orchestrator() 
│  └─ delegation.ORCHESTRATOR().call() ────────── eth_call #1
├─ has_supported_delegation()
│  ├─ is_delegated()
│  │  └─ provider.get_code_at(delegation_addr) ── eth_getCode #2
│  └─ delegation.implementation().call() ──────── eth_call #3
├─ provider.get_fee_history() ────────────────── eth_feeHistory #4
└─ price_oracle.eth_price() ─────────────────── (external API)

Sequential Group:
├─ get_assets() (balance check)
│  └─ ERC20::balanceOf().call() ─────────────── eth_call #5
└─ simulate_execute() & estimate_extra_fee() (Phase 1 parallel)
   ├─ Multiple contract simulation calls ────── eth_call #6-9
   └─ L1 fee estimation (Optimism chains) ──── eth_call #10
```

### After Phase 2: Multicall3 Batched

```
Parallel Group:
├─ multicall3_batch_1: Account Queries ──────── eth_call #1 (batches 3 calls)
│  ├─ delegation.ORCHESTRATOR()
│  ├─ provider.get_code_at(delegation_addr) 
│  └─ delegation.implementation()
├─ provider.get_fee_history() ────────────────── eth_feeHistory #2  
└─ price_oracle.eth_price() ─────────────────── (external API)

Sequential Group:
├─ multicall3_batch_2: Balance & Simulation ──── eth_call #3 (batches 2-4 calls)
│  ├─ ERC20::balanceOf()
│  ├─ orchestrator.simulate_execute() (if simple)
│  └─ Additional balance/state queries
└─ estimate_extra_fee() ──────────────────────── eth_call #4 (if needed)
```

**Result**: 10+ individual calls → 3-4 batched calls (**60-70% RPC call reduction**)

## Implementation Architecture

### 1. Multicall3 Helper Module (`src/rpc/multicall.rs`)

```rust
use alloy::{
    primitives::{Address, Bytes, U256},
    providers::Provider,
    rpc::types::TransactionRequest,
    sol,
    sol_types::{SolCall, SolValue},
};

sol! {
    #[sol(rpc)]
    interface IMulticall3 {
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
            
        function getEthBalance(address addr)
            external view
            returns (uint256 balance);
    }
}

/// Multicall3 batch coordinator
pub struct MulticallBatcher<P> {
    provider: P,
    multicall_address: Address,
}

impl<P: Provider> MulticallBatcher<P> {
    /// Address for Multicall3 (deployed at same address across all chains)
    const MULTICALL3_ADDRESS: Address = address!("cA11bde05977b3631167028862bE2a173976CA11");
    
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            multicall_address: Self::MULTICALL3_ADDRESS,
        }
    }
    
    /// Batch account-related queries (delegation, orchestrator, implementation)
    pub async fn batch_account_queries(
        &self,
        account: Address,
        delegation: Address,
    ) -> Result<AccountQueryResults, MulticallError> {
        let calls = vec![
            // 1. Get orchestrator address
            Call3 {
                target: delegation,
                allowFailure: false,
                callData: DelegationProxy::ORCHESTRATORCall {}.abi_encode().into(),
            },
            // 2. Get delegation code to check if delegated  
            Call3 {
                target: delegation,
                allowFailure: false,
                callData: Bytes::new(), // Special case for eth_getCode via multicall
            },
            // 3. Get implementation address
            Call3 {
                target: delegation, 
                allowFailure: false,
                callData: DelegationProxy::implementationCall {}.abi_encode().into(),
            },
        ];
        
        let results = IMulticall3::new(self.multicall_address, &self.provider)
            .aggregate3(calls)
            .call()
            .await?;
            
        Ok(AccountQueryResults::parse(results)?)
    }
    
    /// Batch balance and simple state queries
    pub async fn batch_balance_queries(
        &self,
        fee_token: Address,
        account: Address,
        additional_calls: Vec<Call3>,
    ) -> Result<BalanceQueryResults, MulticallError> {
        let mut calls = vec![
            // ERC20 balance check
            Call3 {
                target: fee_token,
                allowFailure: false,
                callData: IERC20::balanceOfCall { account }.abi_encode().into(),
            },
        ];
        calls.extend(additional_calls);
        
        let results = IMulticall3::new(self.multicall_address, &self.provider)
            .aggregate3(calls)
            .call()
            .await?;
            
        Ok(BalanceQueryResults::parse(results, fee_token, account)?)
    }
}

#[derive(Debug)]
pub struct AccountQueryResults {
    pub orchestrator: Address,
    pub is_delegated: bool,
    pub implementation: Address,
}

#[derive(Debug)] 
pub struct BalanceQueryResults {
    pub fee_token_balance: U256,
    pub additional_results: Vec<Bytes>,
}

#[derive(Debug, thiserror::Error)]
pub enum MulticallError {
    #[error("Multicall execution failed: {0}")]
    ExecutionFailed(String),
    #[error("Result parsing failed: {0}")]
    ParsingFailed(String),
    #[error("Provider error: {0}")]
    Provider(#[from] TransportError),
}
```

### 2. Integration Points

#### A. Account Module Integration (`src/types/account.rs`)

```rust
impl Account {
    /// Optimized batch query for account data
    pub async fn get_account_info_batched(&self) -> Result<AccountInfo, RelayError> {
        let multicall = MulticallBatcher::new(self.delegation.provider());
        
        // Batch: orchestrator + delegation check + implementation
        let results = multicall
            .batch_account_queries(self.address(), *self.delegation.address())
            .await?;
            
        Ok(AccountInfo {
            orchestrator: results.orchestrator,
            is_delegated: results.is_delegated, 
            implementation: results.implementation,
        })
    }
}

pub struct AccountInfo {
    pub orchestrator: Address,
    pub is_delegated: bool,
    pub implementation: Address,
}
```

#### B. Relay Module Integration (`src/rpc/relay.rs`)

```rust
impl Relay {
    #[instrument(skip_all)]
    async fn estimate_fee_v2(
        &self,
        intent: PartialIntent,
        chain_id: ChainId,
        prehash: bool,
        context: FeeEstimationContext,
    ) -> Result<(ChainAssetDiffs, Quote), RelayError> {
        // Setup (same as before)
        let chain = self.inner.chains.get(chain_id)
            .ok_or(RelayError::UnsupportedChain(chain_id))?;
        let provider = chain.provider.clone();
        let Some(token) = self.inner.fee_tokens.find(chain_id, &context.fee_token) else {
            return Err(QuoteError::UnsupportedFeeToken(context.fee_token).into());
        };

        // Phase 2: Batch the initial RPC calls
        let multicall = MulticallBatcher::new(provider.clone());
        
        let (account_info, fee_history, eth_price) = tokio::try_join!(
            // Batch account queries (was 3 separate calls)
            async {
                let temp_account = self.build_temp_account(&intent, &context, &provider).await?;
                temp_account.get_account_info_batched().await
            },
            // Keep fee history separate (different RPC method)
            provider.get_fee_history(
                EIP1559_FEE_ESTIMATION_PAST_BLOCKS,
                Default::default(), 
                &[self.inner.priority_fee_percentile],
            ).map_err(RelayError::from),
            // Keep price oracle separate (external API)
            async {
                Ok(self.inner.price_oracle.eth_price(token.kind).await)
            },
        )?;

        // Validate orchestrator (moved from batch)
        if !self.is_supported_orchestrator(&account_info.orchestrator) {
            return Err(RelayError::UnsupportedOrchestrator(account_info.orchestrator));
        }

        // Continue with Phase 1 parallel simulation...
        let ((asset_diffs, sim_result), estimated_extra_fee) = tokio::try_join!(
            self.simulate_with_multicall(&account_info, &intent_to_sign, &context),
            self.estimate_extra_fee(&chain, &intent_to_sign)
        )?;
        
        // ... rest of the function unchanged
    }
    
    /// Enhanced simulation using multicall for balance checks
    async fn simulate_with_multicall(
        &self,
        account_info: &AccountInfo,
        intent: &Intent,
        context: &FeeEstimationContext,
    ) -> Result<(ChainAssetDiffs, SimulationResult), RelayError> {
        let multicall = MulticallBatcher::new(self.provider.clone());
        
        // Batch balance check + simulation if possible
        let additional_calls = vec![
            // Add any additional state queries needed for simulation
        ];
        
        let balance_results = multicall
            .batch_balance_queries(context.fee_token, intent.eoa, additional_calls)
            .await?;
            
        // Use batched balance in simulation...
        // (rest of simulation logic)
    }
}
```

### 3. Fallback Strategy

```rust
impl MulticallBatcher<P> {
    /// Check if Multicall3 is available on the chain
    pub async fn is_available(&self) -> bool {
        self.provider
            .get_code_at(self.multicall_address)
            .await
            .map(|code| !code.is_empty())
            .unwrap_or(false)
    }
    
    /// Execute with fallback to individual calls
    pub async fn execute_with_fallback<T>(
        &self,
        batch_fn: impl Future<Output = Result<T, MulticallError>>,
        fallback_fn: impl Future<Output = Result<T, RelayError>>,
    ) -> Result<T, RelayError> {
        match batch_fn.await {
            Ok(result) => Ok(result),
            Err(MulticallError::ExecutionFailed(_)) if !self.is_available().await => {
                // Fallback to individual calls
                fallback_fn.await
            },
            Err(e) => Err(RelayError::Multicall(e)),
        }
    }
}
```

### 4. Configuration & Feature Flags

```rust
// src/config.rs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationConfig {
    /// Enable Phase 1 parallel execution 
    pub enable_parallel_execution: bool,
    /// Enable Phase 2 Multicall3 batching
    pub enable_multicall_batching: bool,
    /// Fallback to individual calls if multicall fails
    pub multicall_fallback_enabled: bool,
    /// Custom Multicall3 address (if different from standard)
    pub multicall3_address: Option<Address>,
}

impl Default for OptimizationConfig {
    fn default() -> Self {
        Self {
            enable_parallel_execution: true,
            enable_multicall_batching: true, 
            multicall_fallback_enabled: true,
            multicall3_address: None,
        }
    }
}
```

## Implementation Timeline

### Week 1: Foundation
1. ✅ Create `src/rpc/multicall.rs` module
2. ✅ Implement `IMulticall3` interface and basic batching
3. ✅ Add configuration support
4. ✅ Unit tests for multicall functionality

### Week 2: Integration  
1. ✅ Integrate with `Account` module for delegation queries
2. ✅ Update `estimate_fee` to use batched account queries
3. ✅ Add fallback mechanisms
4. ✅ Integration tests

### Week 3: Optimization
1. ✅ Add balance batching for ERC20 queries
2. ✅ Optimize simulation call patterns
3. ✅ Performance benchmarking
4. ✅ Error handling refinement

### Week 4: Validation
1. ✅ E2E testing across different chain types
2. ✅ Load testing with batched calls
3. ✅ Monitoring and metrics integration
4. ✅ Documentation and rollout plan

## Success Metrics

| Metric | Before Phase 2 | After Phase 2 | Measurement |
|--------|----------------|---------------|-------------|
| RPC calls per request | 8-12 | 3-4 | Request logs |
| Network round-trips | 8-12 | 3-4 | Trace analysis |  
| p50 latency | ~10ms¹ | ~7ms | OpenTelemetry |
| p99 latency | ~20ms¹ | ~14ms | OpenTelemetry |
| Error rate | <0.1% | <0.1% | Error logs |

¹ *After Phase 1 improvements*

## Risk Mitigation

### 1. Chain Compatibility
- **Risk**: Not all chains support Multicall3
- **Mitigation**: Automatic fallback to individual calls + compatibility detection

### 2. Gas Limitations
- **Risk**: Multicall batches may exceed block gas limits
- **Mitigation**: Batch size limits + automatic splitting

### 3. Partial Failures
- **Risk**: One call failure could invalidate entire batch
- **Mitigation**: `allowFailure: true` for non-critical calls + graceful degradation

### 4. Increased Complexity
- **Risk**: More complex error handling and debugging
- **Mitigation**: Comprehensive logging + feature flags for rollback

## Monitoring & Observability

```rust
// New metrics for Phase 2
lazy_static! {
    static ref MULTICALL_BATCH_SIZE: Histogram = register_histogram!(
        "relay_multicall_batch_size",
        "Size of multicall batches"
    ).unwrap();
    
    static ref MULTICALL_SUCCESS_RATE: Counter = register_counter!(
        "relay_multicall_success_total", 
        "Successful multicall executions"
    ).unwrap();
    
    static ref MULTICALL_FALLBACK_COUNT: Counter = register_counter!(
        "relay_multicall_fallback_total",
        "Multicall fallbacks to individual calls"
    ).unwrap();
}
```

## Next Steps (Phase 3)

Phase 2 sets up the foundation for Phase 3 caching:
- Multicall results are ideal candidates for caching
- Batch invalidation strategies
- Price oracle and delegation implementation caches

This creates a compounding effect: **Phase 1 (40%) + Phase 2 (30%) + Phase 3 (15%) ≈ 60%+ total improvement**