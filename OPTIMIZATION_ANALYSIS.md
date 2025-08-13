# Multicall Optimization Analysis - Issue #1077

## Summary
Analysis of attempting to optimize `estimate_fee` function by parallelizing `account.get_orchestrator()` and `account.delegation_implementation()` calls.

## Issue Description
Original issue #1077 requested implementing Multicall3 batching to reduce RPC calls from 8-12 to 1-3 per request, specifically mentioning batching:
- `account.get_orchestrator()` + `account.delegation_implementation()`
- Multiple `IERC20::balanceOf()` calls in asset queries  
- `get_keys_onchain` delegation checks across multiple accounts

## Implementation Attempted
Modified `estimate_fee` function to execute the two account methods in parallel using `try_join!`:

```rust
let (orchestrator, delegation) = try_join!(
    // Get orchestrator and validate support
    async {
        let orchestrator_addr = account.get_orchestrator().await?;
        if !self.is_supported_orchestrator(&orchestrator_addr) {
            return Err(RelayError::UnsupportedOrchestrator(orchestrator_addr));
        }
        Ok(Orchestrator::new(orchestrator_addr, &provider).with_overrides(overrides))
    },
    // Get delegation and validate support
    self.has_supported_delegation(&account).map_err(RelayError::from)
)?;
```

## Critical Issue Discovered

**Hidden Dependency Chain**: The `delegation_implementation()` method internally calls `get_orchestrator()`:

```rust
// In src/types/account.rs:267
.to(self.get_orchestrator().await?)
```

This creates a call chain:
1. `try_join!` starts both calls in parallel
2. `account.get_orchestrator()` executes (Call #1)
3. `account.delegation_implementation()` starts but internally calls `get_orchestrator()` (Call #2)
4. Both calls hit the same RPC endpoint simultaneously

## Actual Result
- **No parallelization benefit**: `delegation_implementation()` still waits for its internal `get_orchestrator()` call
- **Resource waste**: Two identical RPC calls to `get_orchestrator()` 
- **Potential performance regression**: Network congestion from duplicate requests
- **RPC quota waste**: Uses 2x the expected RPC calls

## Alternative Approaches Considered

### Option 1: Refactor Account Methods
Create `delegation_implementation_with_known_orchestrator(orchestrator: Address)` to break the dependency.

**Pros**: True parallelization possible
**Cons**: Requires API changes, adds complexity, affects multiple call sites

### Option 2: Provider-Level Batching  
Implement JSON-RPC batch requests or use actual Multicall3 contract.

**Pros**: True batching at protocol level, broader benefits
**Cons**: Significant infrastructure change, requires provider modifications

### Option 3: Focus on Other Optimizations
The issue mentioned other areas like `IERC20::balanceOf()` calls and `get_keys_onchain`.

**Current Status**: `get_assets` already uses Alloy's multicall properly for ERC20 queries

## Conclusion

The attempted optimization is **counterproductive** due to hidden dependencies in the Account API. The current code already uses the most efficient approach given the API constraints.

## Recommendations

1. **Revert the change**: Keep original sequential execution to avoid duplicate RPC calls
2. **Future optimization**: If RPC call reduction is critical, consider provider-level batching
3. **Focus elsewhere**: Look for other genuine parallelization opportunities that don't have hidden dependencies

## Impact Assessment

- **Performance**: Current implementation may degrade performance vs sequential
- **Resource usage**: Wastes RPC quota and bandwidth  
- **Correctness**: Functionally correct but inefficient
- **Maintainability**: Adds confusion about actual vs intended behavior

## Lesson Learned

Always trace through the complete call graph when attempting parallelization. Dependencies that aren't obvious from the API surface can defeat optimization attempts.