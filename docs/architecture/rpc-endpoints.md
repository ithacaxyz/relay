# RPC Endpoints Implementation

The Ithaca Relay exposes a JSON-RPC API in the `wallet` namespace for intent preparation, submission, and status tracking.

## Endpoint Overview

| Method | Purpose | Implementation |
|--------|---------|---------------|
| `wallet_prepareCalls` | Prepare intent and generate quote | `src/rpc/relay.rs:1697-1702` |
| `wallet_sendPreparedCalls` | Submit signed intent for execution | `src/rpc/relay.rs:1775-1794` |
| `wallet_getCallsStatus` | Query execution status | `src/rpc/relay.rs:1878-1943` |

## RPC Server Architecture

**Server setup** (**Implementation**: `src/spawn.rs:253-280`):
- Uses `jsonrpsee` framework with `wallet` namespace
- Supports both HTTP and WebSocket transports
- CORS configuration for web clients

**Trait definition** (**Implementation**: `src/rpc/relay.rs:1690-1695`):
```rust
#[rpc(server, client, namespace = "wallet")]
pub trait RelayApi {
    #[method(name = "prepareCalls")]
    async fn prepare_calls(&self, parameters: PrepareCallsParameters) -> RpcResult<PrepareCallsResponse>;
    // ... other methods
}
```

## 1. wallet_prepareCalls

Analyzes an intent, simulates execution, and returns a signed quote for user approval.

### Request Structure

**Type definition** (**Implementation**: `src/types/rpc/calls.rs:45-65`):
```rust
pub struct PrepareCallsParameters {
    pub calls: Vec<Call>,                    // Calls to execute
    pub chain_id: ChainId,                   // Target chain
    pub from: Option<Address>,               // Sender address  
    pub capabilities: PrepareCallsCapabilities,
    pub state_overrides: StateOverride,     // Simulation overrides
    pub balance_overrides: BalanceOverrides, // Balance overrides
    pub key: Option<CallKey>,               // Signing key info
    pub required_funds: Vec<(Address, U256)>, // Required funding
}
```

### Processing Flow

**Main implementation** (**Implementation**: `src/rpc/relay.rs:901-982`):

1. **Request Validation**:
   - Call structure validation
   - Chain support verification
   - Account delegation checking

2. **Strategy Determination**:
   - Single-chain vs multichain analysis
   - Fund sourcing across chains
   - Execution plan generation

3. **Fee Estimation**:
   - Price oracle consultation (**Implementation**: `src/price/oracle.rs:65-90`)
   - Gas estimation via simulation
   - Fee token conversion calculations

4. **Simulation Execution** (**Implementation**: `src/types/orchestrator.rs:198-284`):
   - Off-chain contract simulation
   - Asset diff calculation
   - Gas usage prediction

5. **Quote Generation**:
   - Quote signing with relay's private key
   - EIP-712 digest calculation
   - TTL and expiration setting

### Response Structure

**Type definition** (**Implementation**: `src/types/rpc/calls.rs:85-95`):
```rust
pub struct PrepareCallsResponse {
    pub context: PrepareCallsContext,       // Signed quotes or precall data
    pub digest: B256,                       // EIP-712 hash for user to sign
    pub typed_data: TypedData,              // Full EIP-712 structure  
    pub capabilities: PrepareCallsResponseCapabilities,
    pub key: Option<CallKey>,
}
```

**Context types** (**Implementation**: `src/types/rpc/calls.rs:120-140`):
- **Quotes mode**: Contains signed fee quotes and execution plan
- **Precall mode**: Contains pre-execution call data

## 2. wallet_sendPreparedCalls

Accepts a user-signed intent and submits it for blockchain execution.

### Request Structure  

**Type definition** (**Implementation**: `src/types/rpc/calls.rs:160-170`):
```rust
pub struct SendPreparedCallsParameters {
    pub capabilities: SendPreparedCallsCapabilities,
    pub context: PrepareCallsContext,       // From prepareCalls response
    pub key: CallKey,                       // Signing key information
    pub signature: Bytes,                   // User's signature on digest
}
```

### Processing Flow

**Main implementation** (**Implementation**: `src/rpc/relay.rs:1775-1794`):

1. **Quote Extraction**:
   - Extract signed quotes from context
   - Validate quote presence and format

2. **Signature Verification** (**Implementation**: `src/rpc/relay.rs:451-491`):
   - Quote expiration checking
   - Quote signature validation
   - User signature assembly

3. **Execution Routing**:
   - Single-chain vs multichain routing
   - Bundle ID generation
   - Transaction service integration

4. **Transaction Submission**:
   - **Single-chain** (**Implementation**: `src/rpc/relay.rs:495-550`) - Direct orchestrator call
   - **Multichain** (**Implementation**: `src/rpc/relay.rs:555-650`) - Cross-chain coordination

### Response Structure

**Type definition** (**Implementation**: `src/types/rpc/calls.rs:180-185`):
```rust
pub struct SendPreparedCallsResponse {
    pub id: BundleId,                       // Unique bundle identifier
}
```

The `BundleId` is used for status tracking and is deterministically generated from the quote hash.

## 3. wallet_getCallsStatus

Queries the execution status of a submitted intent bundle.

### Request Structure

**Input**: `BundleId` - The bundle identifier returned from `sendPreparedCalls`

### Processing Flow

**Main implementation** (**Implementation**: `src/rpc/relay.rs:1878-1943`):

1. **Transaction Lookup**:
   - Retrieve all transaction IDs for the bundle
   - Handle bundle-to-transaction mapping

2. **Status Aggregation**:
   - Query individual transaction statuses
   - Aggregate across multiple chains (for multichain)
   - Handle partial execution states

3. **Receipt Processing**:
   - Extract transaction receipts
   - Parse event logs for execution results
   - Detect reverted intents via log analysis

4. **Status Determination**:
   - Calculate overall bundle status
   - Handle edge cases (partial failures, etc.)

### Status Codes

**Status enumeration** (**Implementation**: `src/types/rpc/calls.rs:200-210`):
```rust
pub enum CallStatusCode {
    Pending,              // Still processing
    Confirmed,            // Successfully executed  
    Reverted,             // Execution reverted
    PartiallyReverted,    // Some intents reverted (multichain)
    Failed,               // Broadcast/submission failed
}
```

### Response Structure

**Type definition** (**Implementation**: `src/types/rpc/calls.rs:220-230`):
```rust
pub struct CallsStatus {
    pub id: BundleId,                       // Bundle identifier
    pub status: CallStatusCode,             // Overall execution status
    pub receipts: Vec<CallReceipt>,         // Transaction receipts
}
```

**Receipt details** (**Implementation**: `src/types/rpc/calls.rs:235-250`):
- Transaction hash and block information
- Gas usage and status
- Event logs from contract execution
- Chain ID for multichain operations

## Error Handling

### Common Error Types

**RPC error mapping** (**Implementation**: `src/rpc/relay.rs:50-100`):

| Error Type | HTTP Code | Description |
|------------|-----------|-------------|
| `QuoteError::QuoteExpired` | -32001 | Quote TTL exceeded |
| `QuoteError::InvalidQuoteSignature` | -32002 | Invalid relay signature |
| `IntentError::MissingSender` | -32003 | Missing 'from' address |
| `RelayError::UnsupportedChain` | -32004 | Unsupported chain ID |
| `RelayError::InsufficientFunds` | -32005 | Cannot fulfill funding requirements |

### Error Response Format

**JSON-RPC error structure**:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32001,
    "message": "Quote expired",
    "data": {
      "quote_ttl": 1634567890,
      "current_time": 1634567920
    }
  }
}
```

## Rate Limiting and Security

### Request Validation

**Security checks** (**Implementation**: `src/rpc/relay.rs:200-250`):
- Parameter validation and sanitization
- Chain ID allowlist verification  
- Address format validation
- Call data structure validation

### Rate Limiting

**Implementation considerations**:
- Per-IP rate limiting (configured at reverse proxy level)
- Per-account quote generation limits
- Gas limit enforcement per intent

### Authentication

**Current model**: Open RPC endpoints with no authentication
**Security**: Relies on cryptographic signatures and on-chain validation

## Monitoring and Metrics

### RPC Metrics

**Metrics collection** (**Implementation**: `src/metrics/transport.rs:25-100`):
- Request counts per endpoint
- Response times and latencies
- Error rates and types
- Active connection counts

### Logging

**Request tracing** (**Implementation**: `src/rpc/relay.rs:100-150`):
- Correlation IDs for request tracking
- Parameter logging (with sensitive data redaction)
- Execution time logging
- Error context preservation

## Client Integration

### SDK Integration

The Porto SDK provides a TypeScript interface to these endpoints:

**Example client usage**:
```typescript
// Prepare intent
const response = await relay.prepareCalls({
  calls: [{ to: "0x...", data: "0x...", value: "0" }],
  chainId: 1,
  from: "0x...",
  // ... other parameters
});

// User signs the digest
const signature = await wallet.signTypedData(response.typedData);

// Submit signed intent  
const result = await relay.sendPreparedCalls({
  context: response.context,
  signature,
  key: response.key,
  capabilities: {}
});

// Monitor status
const status = await relay.getCallsStatus(result.id);
```

### Direct JSON-RPC Integration

For non-TypeScript clients, direct JSON-RPC calls can be made:

```bash
# Prepare calls
curl -X POST http://localhost:8323 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "wallet_prepareCalls", 
    "params": {
      "calls": [...],
      "chainId": 1,
      "capabilities": {}
    },
    "id": 1
  }'
```

## Testing RPC Endpoints

### Unit Tests

**Test patterns** (**Implementation**: `tests/e2e/cases/relay.rs:25-100`):
- Mock provider setup
- Request/response validation
- Error condition testing
- Edge case handling

### E2E Tests

**Integration testing** (**Implementation**: `tests/e2e/cases/calls.rs:45-200`):
- Full workflow testing (prepare → send → status)
- Multi-chain intent testing
- Contract interaction validation
- Real blockchain integration

**Test environment setup** (**Implementation**: `tests/e2e/environment.rs:45-120`):
- Automated contract deployment
- Test account funding
- Relay service instantiation

---

## Related Documentation

- **[Transaction Pipeline](transaction-pipeline.md)** - Execution flow after RPC submission
- **[Cross-Chain Operations](cross-chain.md)** - Multichain intent handling
- **[API Reference](../apis/rpc-reference.md)** - Complete API specification

---

💡 **Development Tip**: Use the e2e test cases as examples for implementing RPC endpoint features and understanding the expected request/response patterns.