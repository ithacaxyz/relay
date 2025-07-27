# RPC API Complete Reference

This document provides the comprehensive JSON-RPC API reference for the Ithaca Relay. The API follows JSON-RPC 2.0 specification and provides endpoints in the `wallet` namespace for intent-based transaction processing.

## API Endpoint

**Base URL**: `http://localhost:8323` (default)
**Protocol**: JSON-RPC 2.0
**Namespace**: `wallet`
**Transport**: HTTP POST, WebSocket

## Authentication

**Current Model**: No authentication required
**Security**: Cryptographic signatures provide authorization
**Rate Limiting**: Configurable per-IP limits

## Standard Request Format

```json
{
  "jsonrpc": "2.0",
  "method": "wallet_methodName",
  "params": { /* method parameters */ },
  "id": 1
}
```

## Standard Response Format

```json
{
  "jsonrpc": "2.0",
  "result": { /* method result */ },
  "id": 1
}
```

## Standard Error Format

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32001,
    "message": "Error description",
    "data": { /* additional error context */ }
  },
  "id": 1
}
```

---

## Core Methods

### wallet_prepareCalls

Analyzes an intent, performs execution simulation, and returns a signed quote with execution digest for user approval.

#### Request Parameters

```typescript
interface PrepareCallsParameters {
  calls: Call[]                    // Contract calls to execute
  chainId: number                  // Target blockchain chain ID
  from?: Address                   // Sender account address (optional)
  capabilities?: {                 // Intent capabilities (optional)
    feeToken?: Address             // Token for fee payment
    multiChain?: boolean           // Enable cross-chain execution
  }
  stateOverrides?: StateOverride   // Contract state overrides for simulation
  balanceOverrides?: BalanceOverrides // Account balance overrides
  key?: CallKey                    // Signing key information
  requiredFunds?: [Address, bigint][] // Required funding sources
}

interface Call {
  to: Address                      // Contract address (20 bytes hex)
  data?: Hex                       // Encoded function call data
  value?: bigint                   // ETH value to send (wei)
}

interface CallKey {
  account: Address                 // Account address
  keyType: 'secp256k1' | 'secp256r1' | 'webauthn'
  publicKey?: Hex                  // Public key if available
}
```

#### Response Structure

```typescript
interface PrepareCallsResponse {
  context: PrepareCallsContext     // Signed quotes and execution context
  digest: Hex                      // EIP-712 hash for user to sign
  typedData: TypedData            // Complete EIP-712 structure
  capabilities?: {                 // Response capabilities
    quote?: Quote                  // Fee quote details
    assetDiff?: AssetDiff[]       // Predicted balance changes
  }
  key?: CallKey                    // Key information for signing
}

interface Quote {
  prePaymentAmount: bigint         // Upfront payment amount in fee token
  totalPaymentMaxAmount: bigint    // Maximum total payment in fee token
  feeToken: Address               // Payment token address
  ttl: number                     // Quote expiration timestamp (Unix)
  signature: Hex                  // Relay's cryptographic signature on quote
  nativeFeeEstimate: {            // Native token fee estimates
    maxFeePerGas: bigint
    maxPriorityFeePerGas: bigint
  }
}

interface AssetDiff {
  asset: Address                   // Token contract address
  change: bigint                  // Change amount (positive = incoming)
  chainId: number                 // Chain where change occurs
}
```

#### Error Codes

| Code | Error | Description |
|------|-------|-------------|
| -32003 | `MissingSender` | Missing 'from' address |
| -32004 | `UnsupportedChain` | Chain ID not supported |
| -32005 | `InsufficientFunds` | Cannot fulfill funding requirements |
| -32007 | `SimulationFailed` | Intent simulation failed |

#### Example Request

```json
{
  "jsonrpc": "2.0",
  "method": "wallet_prepareCalls",
  "params": {
    "calls": [
      {
        "to": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        "data": "0x38ed1739000000000000000000000000000000000000000000000000016345785d8a0000000000000000000000000000000000000000000000000000000de0b6b3a7640000",
        "value": "0"
      }
    ],
    "chainId": 1,
    "from": "0x742d35Cc6634C0532925a3b8c17440a75c2D2048",
    "capabilities": {
      "feeToken": "0xA0b86a33E6417c34d4a9b3c0fe3c4b4a3f24F5C9"
    }
  },
  "id": 1
}
```

#### Example Response

```json
{
  "jsonrpc": "2.0",
  "result": {
    "context": {
      "quotes": [
        {
          "prePaymentAmount": "5000000",
          "totalPaymentMaxAmount": "10000000",
          "feeToken": "0xA0b86a33E6417c34d4a9b3c0fe3c4b4a3f24F5C9",
          "ttl": 1634567890,
          "signature": "0x1234...",
          "nativeFeeEstimate": {
            "maxFeePerGas": "30000000000",
            "maxPriorityFeePerGas": "1500000000"
          }
        }
      ]
    },
    "digest": "0xabcd1234...",
    "typedData": {
      "types": {
        "Intent": [
          {"name": "eoa", "type": "address"},
          {"name": "executionData", "type": "bytes"}
        ]
      },
      "primaryType": "Intent",
      "domain": {
        "name": "Ithaca",
        "version": "1",
        "chainId": 1,
        "verifyingContract": "0x..."
      },
      "message": { /* intent data */ }
    },
    "capabilities": {
      "assetDiff": [
        {
          "asset": "0xA0b86a33E6417c34d4a9b3c0fe3c4b4a3f24F5C9",
          "change": "-5000000",
          "chainId": 1
        }
      ]
    }
  },
  "id": 1
}
```

---

### wallet_sendPreparedCalls

Submits a user-signed intent for execution on the blockchain.

#### Request Parameters

```typescript
interface SendPreparedCallsParameters {
  context: PrepareCallsContext     // Context from prepareCalls response
  signature: Hex                   // User's EIP-712 signature on digest
  key: CallKey                     // Signing key information
  capabilities?: {                 // Execution capabilities
    executionMode?: 'async' | 'sync'
  }
}
```

#### Response Structure

```typescript
interface SendPreparedCallsResponse {
  id: BundleId                     // Unique bundle identifier for status tracking
}

type BundleId = Hex                // 32-byte deterministic identifier
```

#### Error Codes

| Code | Error | Description |
|------|-------|-------------|
| -32001 | `QuoteExpired` | Quote TTL exceeded |
| -32002 | `InvalidQuoteSignature` | Invalid relay signature on quote |
| -32006 | `InvalidSignature` | Invalid user signature |

#### Example Request

```json
{
  "jsonrpc": "2.0",
  "method": "wallet_sendPreparedCalls",
  "params": {
    "context": { /* from prepareCalls response */ },
    "signature": "0x1b2c3d4e5f...",
    "key": {
      "account": "0x742d35Cc6634C0532925a3b8c17440a75c2D2048",
      "keyType": "secp256k1"
    },
    "capabilities": {}
  },
  "id": 2
}
```

#### Example Response

```json
{
  "jsonrpc": "2.0",
  "result": {
    "id": "0x9876543210abcdef..."
  },
  "id": 2
}
```

---

### wallet_getCallsStatus

Retrieves the execution status and results of a submitted intent bundle.

#### Request Parameters

```typescript
type GetCallsStatusParameters = BundleId  // Bundle ID from sendPreparedCalls
```

#### Response Structure

```typescript
interface CallsStatus {
  id: BundleId                     // Bundle identifier
  status: CallStatusCode           // Overall execution status
  receipts: CallReceipt[]          // Transaction receipts
}

enum CallStatusCode {
  'pending'                        // Still processing
  'confirmed'                      // Successfully executed
  'reverted'                       // Execution reverted
  'partiallyReverted'             // Some intents reverted (multi-chain)
  'failed'                        // Submission failed
}

interface CallReceipt {
  transactionHash: Hex             // Blockchain transaction hash
  blockNumber: bigint              // Block number
  blockHash: Hex                   // Block hash
  chainId: number                  // Chain ID
  status: 'success' | 'reverted'   // Transaction status
  gasUsed: bigint                  // Gas consumed
  effectiveGasPrice: bigint        // Actual gas price paid
  logs: EventLog[]                 // Contract event logs
}

interface EventLog {
  address: Address                 // Contract that emitted the log
  topics: Hex[]                    // Indexed event parameters
  data: Hex                        // Non-indexed event data
  logIndex: number                 // Log index within transaction
}
```

#### Error Codes

| Code | Error | Description |
|------|-------|-------------|
| -32008 | `BundleNotFound` | Bundle ID not found |

#### Example Request

```json
{
  "jsonrpc": "2.0",
  "method": "wallet_getCallsStatus",
  "params": "0x9876543210abcdef...",
  "id": 3
}
```

#### Example Response

```json
{
  "jsonrpc": "2.0",
  "result": {
    "id": "0x9876543210abcdef...",
    "status": "confirmed",
    "receipts": [
      {
        "transactionHash": "0xdef456...",
        "blockNumber": "18500000",
        "blockHash": "0xabc123...",
        "chainId": 1,
        "status": "success",
        "gasUsed": "120000",
        "effectiveGasPrice": "25000000000",
        "logs": [
          {
            "address": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
            "topics": [
              "0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822"
            ],
            "data": "0x000000000000000000000000...",
            "logIndex": 0
          }
        ]
      }
    ]
  },
  "id": 3
}
```

---

### wallet_getCapabilities

Discovers relay capabilities and supported features.

#### Request Parameters

```typescript
type GetCapabilitiesParameters = {}  // No parameters required
```

#### Response Structure

```typescript
interface RelayCapabilities {
  supportedChains: number[]        // Supported blockchain chain IDs
  supportedFeeTokens: {           // Fee tokens by chain
    [chainId: number]: Address[]
  }
  features: {
    multiChain: boolean            // Cross-chain intent support
    feeAbstraction: boolean        // Fee token abstraction
    gasSponsorship: boolean        // Gas sponsorship capability
    eip1559: boolean              // EIP-1559 fee market support
  }
  limits: {
    maxCalls: number              // Maximum calls per intent
    maxGasLimit: bigint           // Maximum gas limit per intent
    quoteValidity: number         // Quote TTL in seconds
    maxBundleSize: number         // Maximum transactions per bundle
  }
  version: {
    relay: string                 // Relay version
    api: string                   // API version
  }
}
```

#### Example Request

```json
{
  "jsonrpc": "2.0",
  "method": "wallet_getCapabilities",
  "params": {},
  "id": 4
}
```

#### Example Response

```json
{
  "jsonrpc": "2.0",
  "result": {
    "supportedChains": [1, 137, 42161, 8453],
    "supportedFeeTokens": {
      "1": [
        "0xA0b86a33E6417c34d4a9b3c0fe3c4b4a3f24F5C9",
        "0xdAC17F958D2ee523a2206206994597C13D831ec7"
      ],
      "137": [
        "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174"
      ]
    },
    "features": {
      "multiChain": true,
      "feeAbstraction": true,
      "gasSponsorship": true,
      "eip1559": true
    },
    "limits": {
      "maxCalls": 10,
      "maxGasLimit": "10000000",
      "quoteValidity": 300,
      "maxBundleSize": 50
    },
    "version": {
      "relay": "0.1.0",
      "api": "1.0"
    }
  },
  "id": 4
}
```

---

## Extended Methods

### wallet_getAccountInfo

Retrieves account information including delegation status and nonce.

#### Request Parameters

```typescript
interface GetAccountInfoParameters {
  address: Address                 // Account address
  chainId?: number                // Chain ID (optional, defaults to primary)
}
```

#### Response Structure

```typescript
interface AccountInfo {
  address: Address                 // Account address
  isDelegated: boolean            // Whether account has delegation enabled
  delegationProxy?: Address       // Delegation proxy contract address
  nonce: bigint                   // Current account nonce
  balance: {                      // Native token balance
    [chainId: number]: bigint
  }
}
```

#### Example Request

```json
{
  "jsonrpc": "2.0",  
  "method": "wallet_getAccountInfo",
  "params": {
    "address": "0x742d35Cc6634C0532925a3b8c17440a75c2D2048",
    "chainId": 1
  },
  "id": 5
}
```

### wallet_getQuoteHistory

Retrieves historical quotes for analysis and debugging.

#### Request Parameters

```typescript
interface GetQuoteHistoryParameters {
  account?: Address               // Filter by account (optional)
  chainId?: number               // Filter by chain (optional)
  limit?: number                 // Result limit (default: 100)
  offset?: number                // Result offset (default: 0)
}
```

#### Response Structure

```typescript
interface QuoteHistoryResponse {
  quotes: HistoricalQuote[]
  total: number                   // Total matching quotes
  hasMore: boolean               // Whether more results available
}

interface HistoricalQuote {
  id: string                     // Quote identifier
  account: Address               // Account that requested quote
  chainId: number               // Target chain
  feeToken: Address             // Fee payment token
  prePaymentAmount: bigint      // Quote pre-payment
  totalPaymentMaxAmount: bigint // Quote maximum payment
  gasEstimate: bigint           // Estimated gas usage
  createdAt: number             // Creation timestamp
  expiresAt: number             // Expiration timestamp
  used: boolean                 // Whether quote was used
}
```

---

## Error Handling

### Complete Error Code Reference

| Code | Error Type | Description | Recovery |
|------|------------|-------------|----------|
| -32000 | `InternalError` | Internal server error | Retry request |
| -32001 | `QuoteExpired` | Quote TTL exceeded | Get new quote |
| -32002 | `InvalidQuoteSignature` | Invalid relay signature | Report issue |
| -32003 | `MissingSender` | Missing 'from' address | Provide sender |
| -32004 | `UnsupportedChain` | Chain ID not supported | Use supported chain |
| -32005 | `InsufficientFunds` | Cannot fulfill funding | Add funds |
| -32006 | `InvalidSignature` | Invalid user signature | Re-sign with correct key |
| -32007 | `SimulationFailed` | Intent simulation failed | Check call data |
| -32008 | `BundleNotFound` | Bundle ID not found | Verify bundle ID |
| -32009 | `RateLimited` | Too many requests | Reduce request rate |
| -32010 | `InvalidCallData` | Malformed call data | Fix call structure |

### Error Response Structure

```typescript
interface ErrorResponse {
  jsonrpc: '2.0'
  error: {
    code: number                  // Standard error code
    message: string               // Human-readable description
    data?: {                      // Additional error context
      details?: string            // Detailed error information
      retryAfter?: number         // Retry delay in seconds
      [key: string]: any          // Additional context
    }
  }
  id: number | string | null
}
```

### Example Error Response

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32001,
    "message": "Quote expired",
    "data": {
      "quoteTtl": 1634567890,
      "currentTime": 1634567920,
      "quoteHash": "0x1234...",
      "details": "Quote expired 30 seconds ago"
    }
  },
  "id": 1
}
```

---

## WebSocket API

### Connection

```javascript
const ws = new WebSocket('ws://localhost:8323');

// Send JSON-RPC over WebSocket
ws.send(JSON.stringify({
  jsonrpc: '2.0',
  method: 'wallet_prepareCalls',
  params: { /* ... */ },
  id: 1
}));
```

### Subscription Methods

#### wallet_subscribe

Subscribe to real-time bundle status updates.

```json
{
  "jsonrpc": "2.0",
  "method": "wallet_subscribe",
  "params": {
    "bundleId": "0x9876543210abcdef..."
  },
  "id": 1
}
```

#### Status Update Notifications

```json
{
  "jsonrpc": "2.0",
  "method": "wallet_bundleStatusUpdate",
  "params": {
    "bundleId": "0x9876543210abcdef...",
    "status": "confirmed",
    "receipt": { /* transaction receipt */ }
  }
}
```

---

## Rate Limiting

### Default Limits

| Endpoint | Limit | Window |
|----------|-------|--------|
| `wallet_prepareCalls` | 60 requests | 1 minute |
| `wallet_sendPreparedCalls` | 30 requests | 1 minute |
| `wallet_getCallsStatus` | 120 requests | 1 minute |
| `wallet_getCapabilities` | 10 requests | 1 minute |

### Rate Limit Headers

Response headers indicate current rate limit status:

```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1634567890
```

### Rate Limit Error

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32009,
    "message": "Rate limit exceeded",
    "data": {
      "limit": 60,
      "window": 60,
      "retryAfter": 30
    }
  },
  "id": 1
}
```

---

## Client Libraries

### TypeScript/JavaScript

```typescript
import { createRelayClient } from '@ithacaxyz/relay-client'

const client = createRelayClient({
  transport: http('http://localhost:8323')
})

// Prepare intent
const prepared = await client.prepareCalls({
  calls: [transferCall],
  chainId: 1,
  capabilities: { feeToken: usdcAddress }
})

// Submit intent
const { id } = await client.sendPreparedCalls({
  context: prepared.context,
  signature: userSignature,
  key: prepared.key
})

// Monitor status
const status = await client.getCallsStatus(id)
```

### Python

```python
import requests
import json

class RelayClient:
    def __init__(self, url="http://localhost:8323"):
        self.url = url
        self.session = requests.Session()
    
    def _request(self, method, params):
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        }
        
        response = self.session.post(
            self.url,
            json=payload,
            headers={"Content-Type": "application/json"}
        )
        
        result = response.json()
        if "error" in result:
            raise Exception(f"RPC Error: {result['error']}")
        
        return result["result"]
    
    def prepare_calls(self, calls, chain_id, **kwargs):
        return self._request("wallet_prepareCalls", {
            "calls": calls,
            "chainId": chain_id,
            **kwargs
        })
```

### Rust

```rust
use reqwest::Client;
use serde_json::{json, Value};

pub struct RelayClient {
    client: Client,
    url: String,
}

impl RelayClient {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            client: Client::new(),
            url: url.into(),
        }
    }
    
    pub async fn prepare_calls(
        &self,
        calls: Vec<Call>,
        chain_id: u64,
    ) -> Result<PrepareCallsResponse, Box<dyn std::error::Error>> {
        let payload = json!({
            "jsonrpc": "2.0",
            "method": "wallet_prepareCalls",
            "params": {
                "calls": calls,
                "chainId": chain_id
            },
            "id": 1
        });
        
        let response = self.client
            .post(&self.url)
            .json(&payload)
            .send()
            .await?;
        
        let result: Value = response.json().await?;
        
        if result.get("error").is_some() {
            return Err(format!("RPC Error: {:?}", result["error"]).into());
        }
        
        Ok(serde_json::from_value(result["result"].clone())?)
    }
}
```

---

## Testing

### Local Development

```bash
# Start local relay
cargo run --bin relay -- --config relay.yaml

# Test basic connectivity
curl -X POST http://localhost:8323 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"wallet_getCapabilities","params":{},"id":1}'
```

### Integration Testing

```javascript
describe('Relay RPC API', () => {
  test('prepare and execute intent', async () => {
    // Prepare intent
    const prepared = await relay.prepareCalls({
      calls: [{ to: tokenAddress, data: transferData }],
      chainId: 1,
      from: userAddress,
      capabilities: { feeToken: usdcAddress }
    })
    
    expect(prepared.digest).toBeDefined()
    expect(prepared.context.quotes).toHaveLength(1)
    
    // Sign digest
    const signature = await wallet.signTypedData(prepared.typedData)
    
    // Submit intent
    const { id } = await relay.sendPreparedCalls({
      context: prepared.context,
      signature,
      key: prepared.key
    })
    
    expect(id).toMatch(/^0x[a-fA-F0-9]{64}$/)
    
    // Monitor status
    await waitFor(async () => {
      const status = await relay.getCallsStatus(id)
      expect(status.status).toBe('confirmed')
    })
  })
})
```

---

## Related Documentation

- **[RPC Endpoints](../architecture/rpc-endpoints.md)** - Implementation details
- **[Transaction Pipeline](../architecture/transaction-pipeline.md)** - Processing flow
- **[Getting Started](../development/getting-started.md)** - Development setup
- **[Testing Guide](../development/testing.md)** - Testing patterns

---

💡 **Development Tip**: Use the WebSocket API for real-time status updates in production applications. It provides better user experience and reduces polling overhead.