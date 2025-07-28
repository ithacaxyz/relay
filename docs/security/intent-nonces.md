# Intent Nonce Specification

This document provides the complete technical specification for the 256-bit Intent nonce system used in the Ithaca Relay. The nonce system enables flexible transaction ordering, replay protection, and cross-chain coordination through a sophisticated bit layout and sequence key mechanism.

## 256-Bit Nonce Structure

### Memory Layout

The Intent nonce uses a 256-bit structure with specific bit allocations for different purposes:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           256-bit Intent Nonce                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│                    Bits 0-191 (192 bits)                  │  Bits 192-255      │
│                   Sequence Key                            │  (64 bits)         │
│                                                          │  Sequential Nonce  │
├─────────────────────────────────────────────────────────────────────────────────┤
│ Bits 0-15      │                Bits 16-191                                    │ 
│ (16 bits)      │                (176 bits)                                     │
│ Multichain     │                User-Defined                                    │
│ Flag           │                Sequence Identifier                             │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Bit Field Definitions

#### Sequence Key (Bits 0-191)
**Size**: 192 bits
**Purpose**: Defines the sequence context for ordering and replay protection

**Sub-fields**:
- **Multichain Flag (Bits 0-15)**: Special prefix for cross-chain intents
- **User-Defined Identifier (Bits 16-191)**: Application-specific sequence identification

#### Sequential Nonce (Bits 192-255)  
**Size**: 64 bits
**Purpose**: Monotonic counter within each sequence key
**Range**: 0 to 2^64 - 1 (18,446,744,073,709,551,615)

### Implementation Constants

**File**: `src/types/intent.rs:26-30`

```rust
/// Nonce prefix to signal that the payload is to be signed with EIP-712 without the chain ID.
pub const MULTICHAIN_NONCE_PREFIX: U256 = uint!(0xc1d0_U256);

/// Nonce prefix to signal that the payload is to be signed with EIP-712 without the chain ID.
pub const MULTICHAIN_NONCE_PREFIX_U192: U192 = uint!(0xc1d0_U192);
```

## Multichain Prefix System

### Purpose
The multichain prefix `0xc1d0` in the upper 16 bits signals that an intent should be processed with chain-agnostic EIP-712 signatures, enabling atomic cross-chain execution.

### Detection Logic
**Implementation**: `src/types/intent.rs:452-454`

```rust
fn is_multichain(&self) -> bool {
    self.nonce() >> 240 == MULTICHAIN_NONCE_PREFIX
}
```

**Bit Operation Breakdown**:
1. `self.nonce()` - Get the full 256-bit nonce
2. `>> 240` - Right-shift by 240 bits to isolate upper 16 bits  
3. `== MULTICHAIN_NONCE_PREFIX` - Compare with `0xc1d0`

### EIP-712 Domain Impact
When multichain flag is detected, the EIP-712 domain excludes the chain ID:

**Implementation**: `src/types/orchestrator.rs:315-321`

```rust
Ok(Eip712Domain::new(
    Some(domain.name.into()),
    Some(domain.version.into()),
    (!multichain).then_some(domain.chainId),  // Chain ID excluded if multichain
    Some(domain.verifyingContract),
    None,
))
```

**Security Properties**:
- **Cross-Chain Validity**: Same signature valid across all chains
- **Atomic Coordination**: Enables synchronized execution
- **Controlled Replay**: Intentional cross-chain replay for atomic operations

## Sequence Key Generation

### Random Sequence Keys
For independent operations that don't require ordering:

```rust
use rand::RngCore;

fn generate_random_sequence_key() -> U192 {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 24]; // 192 bits = 24 bytes
    rng.fill_bytes(&mut bytes);
    U192::from_be_bytes(bytes)
}
```

### Multichain Sequence Keys
For cross-chain atomic operations:

```rust
fn generate_multichain_sequence_key() -> U192 {
    let mut sequence_key = generate_random_sequence_key();
    // Set upper 16 bits to multichain prefix
    sequence_key |= U192::from(MULTICHAIN_NONCE_PREFIX_U192);
    sequence_key
}
```

### Deterministic Sequence Keys
For reproducible testing or specific use cases:

```rust
use alloy::primitives::keccak256;

fn generate_deterministic_sequence_key(seed: &str) -> U192 {
    let hash = keccak256(seed.as_bytes());
    // Use first 192 bits of hash
    let mut bytes = [0u8; 24];
    bytes.copy_from_slice(&hash[..24]);
    U192::from_be_bytes(bytes)
}
```

## Sequence Key Semantics

### Ordering Rules

#### Within Sequence (Strict Ordering)
Intents within the same sequence key MUST be executed in sequential nonce order:

```rust
fn validate_sequence_ordering(
    current_nonce: u64, 
    expected_nonce: u64
) -> Result<(), ValidationError> {
    if current_nonce != expected_nonce {
        return Err(ValidationError::InvalidSequenceOrder {
            expected: expected_nonce,
            received: current_nonce,
        });
    }
    Ok(())
}
```

**Properties**:
- **No Gaps**: Cannot skip sequence positions (e.g., cannot go from nonce 5 to nonce 7)
- **No Reordering**: Must execute nonce 6 before nonce 7
- **Atomic Incrementing**: Sequence position advances atomically with successful execution

#### Between Sequences (No Ordering)
Intents with different sequence keys can execute in any order:

```rust
// These can execute in parallel or any order
let sequence_a = generate_random_sequence_key();
let sequence_b = generate_random_sequence_key(); 

let intent_a1 = create_intent(sequence_a, 1);
let intent_a2 = create_intent(sequence_a, 2);
let intent_b1 = create_intent(sequence_b, 1);
let intent_b2 = create_intent(sequence_b, 2);

// Valid execution orders:
// A1, A2, B1, B2
// B1, A1, B2, A2  
// A1, B1, A2, B2
// etc.
```

### Use Case Patterns

#### Pattern 1: Independent Operations
**Use Case**: Multiple unrelated transactions that can execute in parallel
**Implementation**: Use different sequence keys for each operation

```rust
// User wants to swap tokens and update profile simultaneously
let swap_sequence = generate_random_sequence_key();
let profile_sequence = generate_random_sequence_key();

let swap_intent = create_swap_intent(swap_sequence, 1, token_a, token_b, amount);
let profile_intent = create_profile_intent(profile_sequence, 1, new_profile_data);

// These can execute in any order
```

#### Pattern 2: Dependent Operations  
**Use Case**: Operations that must execute in specific order
**Implementation**: Use same sequence key with sequential nonces

```rust
// User wants to approve tokens then perform swap
let trading_sequence = generate_random_sequence_key();

let approve_intent = create_approve_intent(trading_sequence, 1, token, spender, amount);
let swap_intent = create_swap_intent(trading_sequence, 2, token_a, token_b, amount);

// Must execute approve_intent before swap_intent
```

#### Pattern 3: Cross-Chain Atomic Operations
**Use Case**: Operations that must succeed or fail together across chains
**Implementation**: Use multichain sequence key

```rust
// User wants atomic swap across Ethereum and Polygon
let atomic_sequence = generate_multichain_sequence_key();

let eth_intent = create_bridge_intent(
    atomic_sequence, 1, ETHEREUM_CHAIN_ID, token, amount, destination
);
let polygon_intent = create_receive_intent(
    atomic_sequence, 2, POLYGON_CHAIN_ID, token, amount, source
);

// Both must succeed or both fail
```

#### Pattern 4: Batch Operations with Error Handling
**Use Case**: Multiple operations where some failures are acceptable
**Implementation**: Use different sequence keys with error handling logic

```rust
// User wants to attempt multiple DeFi strategies
let strategies = vec![
    generate_random_sequence_key(), // Strategy A
    generate_random_sequence_key(), // Strategy B  
    generate_random_sequence_key(), // Strategy C
];

for (i, strategy_key) in strategies.iter().enumerate() {
    let intent = create_strategy_intent(*strategy_key, 1, strategy_params[i]);
    // Each strategy can fail independently
}
```

## Nonce Construction and Parsing

### Construction Functions

#### Basic Nonce Construction
```rust
fn construct_nonce(sequence_key: U192, sequential_nonce: u64) -> U256 {
    let sequence_part = U256::from(sequence_key) << 64;
    let nonce_part = U256::from(sequential_nonce);
    sequence_part | nonce_part
}
```

#### Multichain Nonce Construction
```rust
fn construct_multichain_nonce(user_sequence: U176, sequential_nonce: u64) -> U256 {
    let multichain_prefix = U256::from(MULTICHAIN_NONCE_PREFIX) << 240;
    let user_part = U256::from(user_sequence) << 64;
    let nonce_part = U256::from(sequential_nonce);
    multichain_prefix | user_part | nonce_part
}
```

### Parsing Functions

#### Extract Sequence Key
```rust
fn extract_sequence_key(nonce: U256) -> U192 {
    let sequence_bits = nonce >> 64;
    U192::try_from(sequence_bits).expect("Sequence key should fit in 192 bits")
}
```

#### Extract Sequential Nonce
```rust
fn extract_sequential_nonce(nonce: U256) -> u64 {
    (nonce & U256::from(u64::MAX)).try_into().expect("Should fit in u64")
}
```

#### Check Multichain Flag
```rust
fn is_multichain_nonce(nonce: U256) -> bool {
    (nonce >> 240) == MULTICHAIN_NONCE_PREFIX
}
```

#### Extract User Sequence (for multichain)
```rust
fn extract_user_sequence(nonce: U256) -> U176 {
    assert!(is_multichain_nonce(nonce), "Not a multichain nonce");
    let user_bits = (nonce >> 64) & U256::from((1u128 << 176) - 1);
    U176::try_from(user_bits).expect("User sequence should fit in 176 bits")
}
```

## PreCall Nonce Isolation

### Purpose
PreCalls (nested intents) use independent nonce validation to enable complex execution patterns while maintaining security.

### Implementation
**File**: `src/types/intent.rs:94-102`

```rust
/// Optional array of encoded Intents that will be verified and executed
/// after PREP (if any) and before the validation of the overall Intent.
/// A PreCall will NOT have its gas limit or payment applied.
/// The overall Intent's gas limit and payment will be applied, encompassing all its PreCalls.
/// The execution of a PreCall will check and increment the nonce in the PreCall.
bytes[] encodedPreCalls;
```

### Nonce Validation Flow
1. **Parent Intent**: Validates its own nonce against EOA's sequence state
2. **PreCall Validation**: Each PreCall validates its nonce independently  
3. **Execution Order**: PreCalls execute in post-order (left → right → current)
4. **Failure Propagation**: Any PreCall failure causes parent intent failure

### Security Properties
- **Isolation**: PreCall nonces don't interfere with parent intent nonce
- **Independence**: PreCalls can use different sequence keys from parent
- **Atomicity**: All PreCalls and parent intent succeed or all fail
- **Replay Protection**: PreCall nonces are validated and consumed independently

## Error Handling and Edge Cases

### Nonce Overflow
**Scenario**: Sequential nonce exceeds 64-bit maximum

```rust
fn handle_nonce_overflow(sequence_key: U192, current_nonce: u64) -> Result<U256, NonceError> {
    if current_nonce == u64::MAX {
        return Err(NonceError::SequenceExhausted { 
            sequence_key,
            suggestion: "Generate new sequence key".into(),
        });
    }
    Ok(construct_nonce(sequence_key, current_nonce + 1))
}
```

**Mitigation**: Generate new sequence key when approaching overflow

### Sequence Key Collision
**Scenario**: Two users generate identical sequence keys

**Probability**: Negligible with 176-bit user-defined space (2^176 ≈ 9.5 × 10^52)

**Mitigation**: Use cryptographically secure random generation

### Invalid Nonce Format
**Scenario**: Malformed nonce that doesn't conform to specification

```rust
fn validate_nonce_format(nonce: U256) -> Result<(), ValidationError> {
    let sequence_key = extract_sequence_key(nonce);
    let sequential_nonce = extract_sequential_nonce(nonce);
    
    // Validate sequential nonce is not zero (nonces start at 1)
    if sequential_nonce == 0 {
        return Err(ValidationError::InvalidSequentialNonce);
    }
    
    // Additional format validations...
    Ok(())
}
```

### Multichain Nonce Misuse
**Scenario**: Single-chain intent using multichain prefix

**Detection**: Check intent type matches nonce type

```rust
fn validate_nonce_intent_consistency(
    intent: &Intent, 
    nonce: U256
) -> Result<(), ValidationError> {
    let is_multichain_nonce = is_multichain_nonce(nonce);
    let is_multichain_intent = intent.is_multichain();
    
    if is_multichain_nonce != is_multichain_intent {
        return Err(ValidationError::NonceIntentMismatch {
            nonce_type: if is_multichain_nonce { "multichain" } else { "single-chain" },
            intent_type: if is_multichain_intent { "multichain" } else { "single-chain" },
        });
    }
    
    Ok(())
}
```

## Integration Examples

### SDK Integration Pattern
```typescript
// TypeScript SDK example
class IntentBuilder {
    private sequenceKey: string;
    private nextNonce: number = 1;

    constructor(isMultichain: boolean = false) {
        if (isMultichain) {
            this.sequenceKey = this.generateMultichainSequenceKey();
        } else {
            this.sequenceKey = this.generateRandomSequenceKey();
        }
    }

    buildIntent(calls: Call[]): Intent {
        const nonce = this.constructNonce(this.sequenceKey, this.nextNonce);
        this.nextNonce++; // Increment for next intent
        
        return {
            eoa: this.userAddress,
            executionData: encodeCalls(calls),
            nonce: nonce,
            // ... other fields
        };
    }
}
```

### Contract Integration Pattern
```solidity
// Solidity contract example
contract IntentProcessor {
    mapping(address => mapping(uint256 => uint256)) public sequencePositions;
    
    function validateAndUpdateNonce(
        address eoa,
        uint256 nonce
    ) internal {
        uint256 sequenceKey = nonce >> 64;
        uint256 sequentialNonce = nonce & 0xFFFFFFFFFFFFFFFF;
        
        uint256 currentPosition = sequencePositions[eoa][sequenceKey];
        require(
            sequentialNonce == currentPosition + 1,
            "Invalid sequence order"
        );
        
        sequencePositions[eoa][sequenceKey] = sequentialNonce;
    }
}
```

## Testing and Validation

### Unit Test Examples
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_construction_and_parsing() {
        let sequence_key = U192::from(0x123456789ABCDEF);
        let sequential_nonce = 42u64;
        
        let nonce = construct_nonce(sequence_key, sequential_nonce);
        
        assert_eq!(extract_sequence_key(nonce), sequence_key);
        assert_eq!(extract_sequential_nonce(nonce), sequential_nonce);
    }

    #[test]
    fn test_multichain_detection() {
        let multichain_nonce = construct_multichain_nonce(U176::from(123), 1);
        let regular_nonce = construct_nonce(U192::from(123), 1);
        
        assert!(is_multichain_nonce(multichain_nonce));
        assert!(!is_multichain_nonce(regular_nonce));
    }

    #[test]
    fn test_sequence_ordering() {
        let sequence_key = generate_random_sequence_key();
        
        // Valid sequence
        assert!(validate_sequence_ordering(1, 1).is_ok());
        assert!(validate_sequence_ordering(2, 2).is_ok());
        
        // Invalid sequence (gap)
        assert!(validate_sequence_ordering(3, 1).is_err());
        assert!(validate_sequence_ordering(1, 3).is_err());
    }
}
```

### Integration Test Scenarios
```rust
#[tokio::test]
async fn test_multichain_atomic_execution() {
    let multichain_sequence = generate_multichain_sequence_key();
    
    // Create intents for different chains with same sequence
    let eth_intent = create_intent(ETHEREUM, multichain_sequence, 1);
    let polygon_intent = create_intent(POLYGON, multichain_sequence, 2);
    
    // Execute atomically - both should succeed or both fail
    let result = execute_multichain_bundle(vec![eth_intent, polygon_intent]).await;
    assert!(result.is_ok());
    
    // Verify nonces consumed on both chains
    assert_eq!(get_sequence_position(ETHEREUM, eoa, multichain_sequence).await, 1);
    assert_eq!(get_sequence_position(POLYGON, eoa, multichain_sequence).await, 2);
}
```

## Performance Considerations

### Nonce Storage Optimization
- **Sparse Storage**: Only store consumed nonces, not full sequence ranges
- **Efficient Indexing**: Use hash-based indexing for O(1) nonce lookups
- **Cleanup Strategy**: Implement periodic cleanup of old expired nonces

### Sequence Key Generation
- **Hardware Random**: Use hardware-based random number generation when available
- **Entropy Pool**: Maintain sufficient entropy for cryptographic randomness
- **Performance**: Balance security with generation speed for high-throughput applications

### Validation Performance
- **Bit Operations**: Use efficient bit manipulation for nonce parsing
- **Caching**: Cache recently validated sequence states for repeated access
- **Parallel Validation**: Validate multiple intents concurrently when possible

## Related Documentation

- **[Nonce Protection](nonce-protection.md)** - Multi-layered nonce system overview
- **[Replay Prevention](replay-prevention.md)** - Comprehensive replay attack prevention
- **[Cross-Chain Security](cross-chain-security.md)** - Multichain coordination security