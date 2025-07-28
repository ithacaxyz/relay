# Multi-Layered Nonce Protection

The Ithaca Relay implements a sophisticated multi-layered nonce protection system that prevents replay attacks and ensures transaction ordering across multiple contexts. This document details the three distinct nonce layers and how they coordinate to provide comprehensive protection.

## Overview

The relay's nonce protection operates at three distinct layers:

1. **Ethereum Transaction Nonces** - Standard blockchain transaction ordering
2. **Intent Nonces** - 256-bit application-level replay protection with sequence keys
3. **EIP-7702 Delegation Nonces** - Contract-level delegation state management

Each layer serves a specific purpose and together they create a robust defense against replay attacks, transaction reordering, and unauthorized execution.

## Layer 1: MultiChainNonceManager

### Purpose
Manages Ethereum transaction nonces across multiple chains and addresses to ensure proper transaction ordering at the blockchain level.

### Implementation
**File**: `src/nonce.rs`

```rust
pub struct MultiChainNonceManager {
    nonces: Arc<DashMap<(ChainId, Address), Arc<Mutex<u64>>>>,
}
```

### Key Features

#### Per-Chain, Per-Address Nonce Tracking
- Maintains separate nonce counters for each `(chain_id, address)` pair
- Prevents nonce conflicts in multichain operations
- Uses thread-safe `DashMap` for concurrent access

#### Atomic Nonce Allocation
The manager provides atomic nonce allocation with lazy initialization:

```rust
async fn get_next_nonce<P, N>(
    &self,
    provider: &P,
    address: Address,
) -> alloy::transports::TransportResult<u64>
```

**Process**:
1. Check if nonce exists for `(chain_id, address)` pair
2. If not found, fetch current nonce from blockchain via `provider.get_transaction_count()`
3. If exists, increment cached nonce atomically
4. Return next available nonce

#### Security Properties
- **Monotonic Ordering**: Nonces strictly increase, preventing transaction reordering
- **Race Condition Protection**: Mutex ensures atomic nonce updates
- **Chain Isolation**: Nonces are isolated per chain, preventing cross-chain conflicts
- **Recovery Capability**: Re-synchronizes with blockchain if cache becomes inconsistent

## Layer 2: Intent Nonce System

### Purpose
Provides application-level replay protection with flexible ordering semantics through sequence keys.

### 256-Bit Nonce Structure
**Implementation**: `src/types/intent.rs:50-77`

```
┌─────────────────────────────────────────────────────────────────────┐
│                           256-bit Intent Nonce                     │
├─────────────────────────────────────────────────────────────────────┤
│ bits 0-191 (192 bits)              │ bits 192-255 (64 bits)        │
│ Sequence Key                        │ Sequential Nonce               │
├─────────────────────────────────────────────────────────────────────┤
│ bits 0-15    │ bits 16-191                                          │
│ Multichain   │ User-defined                                         │
│ Flag (0xc1d0)│ Sequence Identifier                                 │
└─────────────────────────────────────────────────────────────────────┘
```

### Multichain Prefix Detection
**Constant**: `MULTICHAIN_NONCE_PREFIX = 0xc1d0`

When the upper 16 bits of the sequence key equal `0xc1d0`, the intent is processed as multichain:
- EIP-712 domain excludes chain ID for cross-chain signature compatibility
- Enables atomic execution across multiple chains

**Implementation**: `src/types/intent.rs:453`
```rust
fn is_multichain(&self) -> bool {
    self.nonce() >> 240 == MULTICHAIN_NONCE_PREFIX
}
```

### Sequence Key Semantics

#### Ordering Rules
- **Within Sequence**: Strict sequential ordering enforced (nonces must be consecutive)
- **Between Sequences**: No ordering constraints (enables parallel execution)

#### Use Cases
1. **Dependent Operations**: Use same sequence key for operations that must execute in order
2. **Independent Operations**: Use different sequence keys for parallel execution
3. **Cross-Chain Coordination**: Use multichain prefix for atomic cross-chain operations

### Security Properties
- **Replay Prevention**: Each nonce can only be used once per EOA
- **Sequence Isolation**: Users can have multiple independent transaction sequences
- **Cross-Chain Consistency**: Multichain intents use chain-agnostic signatures
- **Flexible Ordering**: Balances strict ordering with parallel execution capabilities

## Layer 3: EIP-7702 Delegation Nonces

### Purpose
Manages delegation-specific nonces for EIP-7702 account implementations to prevent delegation replay attacks.

### Delegation Context
EIP-7702 allows EOAs to delegate to smart contract implementations. The relay must track:
- Current delegation state
- Delegation-specific operation nonces
- Authorization boundaries per delegation

### Implementation Details
**File**: `src/types/account.rs`

#### Default Sequence Key
```rust
pub const DEFAULT_SEQUENCE_KEY: U192 = uint!(0_U192);
```

Used for standard delegation operations when no specific sequence is required.

#### Account Implementation Validation
**File**: `src/types/orchestrator.rs:146-150`

```rust
function accountImplementationOf(address eoa) public view virtual returns (address result);
```

The orchestrator validates that:
1. EOA has valid EIP-7702 delegation
2. Delegation points to expected account implementation
3. Account implementation supports required operations

### Security Properties
- **Delegation Isolation**: Nonces are scoped to specific delegation contexts
- **Implementation Validation**: Ensures delegated account matches expected interface
- **Authorization Boundaries**: Enforces permission limits within delegated execution

## Nonce Coordination Mechanisms

### Intent Processing Pipeline
The three nonce layers coordinate during intent processing:

1. **Intent Validation** (`src/rpc/relay.rs`)
   - Validates intent nonce format and sequence
   - Checks for replay attempts
   - Verifies sequence key constraints

2. **Transaction Assembly** (`src/transactions/signer.rs`)
   - Allocates Ethereum transaction nonce via MultiChainNonceManager
   - Embeds intent nonce in transaction data
   - Maintains nonce mapping for monitoring

3. **Contract Execution** (Orchestrator Contract)
   - Validates intent nonce uniqueness
   - Increments sequence counters
   - Emits nonce invalidation events

### Event-Based Nonce Tracking
**Implementation**: `src/types/orchestrator.rs:38-42`

```rust
event IntentExecuted(
    address indexed eoa, 
    uint256 indexed nonce, 
    bool incremented, 
    bytes4 err
);
```

The `incremented` flag indicates whether the nonce sequence was advanced, providing:
- **Execution Confirmation**: Nonce was consumed successfully
- **Error Handling**: Failed intents may or may not consume nonces depending on error type
- **State Synchronization**: Relay can track nonce state changes

### Nonce State Recovery
In case of network issues or relay restarts, the system can recover nonce state:

1. **Blockchain Query**: Fetch current on-chain nonce state from orchestrator
2. **Event Log Analysis**: Replay recent `IntentExecuted` events to reconstruct state
3. **Cache Resynchronization**: Update MultiChainNonceManager with recovered state

## Security Attack Vectors and Mitigations

### Replay Attack Prevention

#### Same-Chain Replays
- **Mitigation**: Intent nonces are tracked on-chain and can only be used once
- **Implementation**: Orchestrator contract maintains nonce state per EOA
- **Recovery**: Failed transactions may preserve nonces depending on failure point

#### Cross-Chain Replays
- **Mitigation**: Multichain intents use chain-agnostic signatures with shared nonce space
- **Implementation**: Sequence keys with multichain prefix (0xc1d0) create global ordering
- **Validation**: Each chain validates against the same multichain nonce sequence

### Transaction Reordering Attacks

#### Within Sequence Protection
- **Mitigation**: Sequential nonces within same sequence key must be consecutive
- **Implementation**: Contract enforces strict ordering for same sequence key
- **User Control**: Users choose sequence keys based on ordering requirements

#### MEV and Front-Running Protection
- **Mitigation**: Intent-based execution obscures transaction details until execution
- **Implementation**: Encrypted execution data until on-chain processing
- **Coordination**: Relay coordinates execution timing across chains

### Nonce Exhaustion Attacks

#### Sequence Key Space
- **Protection**: 176-bit user-defined sequence space provides 2^176 possible sequences
- **Implementation**: Users can generate new sequence keys as needed
- **Mitigation**: Sequence keys are user-controlled, preventing external exhaustion

#### Economic Protection
- **Gas Costs**: Each intent execution requires gas payment, making spam expensive
- **Rate Limiting**: Relay implements per-EOA rate limiting (implementation-dependent)
- **Quote System**: Pre-execution validation ensures sufficient funds for gas

## Best Practices for Developers

### Sequence Key Selection
1. **Related Operations**: Use same sequence key for operations with dependencies
2. **Independent Operations**: Use different sequence keys for parallel execution
3. **Cross-Chain Operations**: Use multichain prefix (0xc1d0) for atomic cross-chain intents
4. **Key Generation**: Use cryptographically secure random generation for sequence keys

### Error Handling
1. **Monitor IntentExecuted Events**: Check `incremented` flag to confirm nonce consumption
2. **Handle Partial Failures**: Some errors may consume nonces while others preserve them
3. **Nonce Recovery**: Implement retry logic that accounts for nonce state changes

### Integration Patterns
1. **SDK Integration**: Use provided Porto SDK for proper nonce management
2. **Custom Integrations**: Implement proper nonce tracking and sequence management
3. **Testing**: Use separate sequence keys for test environments to avoid conflicts

## Monitoring and Diagnostics

### Nonce State Inspection
- **Contract Queries**: Query orchestrator contract for current nonce state
- **Event Logs**: Analyze `IntentExecuted` events for nonce consumption patterns
- **Relay Metrics**: Monitor nonce allocation rates and sequence utilization

### Common Issues and Resolution
1. **Nonce Gaps**: Check for failed transactions that consumed nonces
2. **Sequence Conflicts**: Verify sequence key generation and usage patterns
3. **Cross-Chain Synchronization**: Monitor multichain nonce coordination across chains

## Related Documentation

- **[Intent Nonces](intent-nonces.md)** - Detailed 256-bit nonce specification
- **[Replay Prevention](replay-prevention.md)** - Comprehensive replay attack mitigation
- **[Cross-Chain Security](cross-chain-security.md)** - Multichain coordination security