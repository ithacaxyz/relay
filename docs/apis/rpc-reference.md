# RPC API Reference

Complete reference for the Ithaca Relay JSON-RPC API endpoints.

## Base Configuration

**Base URL**: `http://localhost:8323` (default)  
**Protocol**: JSON-RPC 2.0  
**Content-Type**: `application/json`

## Wallet Namespace

All relay endpoints are under the `wallet_` namespace.

### `wallet_getCapabilities`

Retrieve relay capabilities and supported features.

**Method**: `wallet_getCapabilities`  
**Parameters**: `{}`

#### Request Example

```bash
curl -X POST http://localhost:8323 \
  -H "Content-Type: application/json" \
  -d '{
    "method": "wallet_getCapabilities",
    "params": {},
    "id": 1,
    "jsonrpc": "2.0"
  }'
```

#### Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "0x7a69": {
      "paymasterService": {
        "supported": true
      },
      "sessionKeys": {
        "supported": true
      }
    }
  }
}
```

### `wallet_prepareCalls`

Prepare intent execution and generate fee quote.

**Method**: `wallet_prepareCalls`  
**Parameters**: `PrepareCallsParameters`

#### Parameters

```typescript
interface PrepareCallsParameters {
  version: string;           // API version (e.g., "1.0")
  chainId: string;          // Target chain ID (hex)
  from: string;             // Account address
  calls: Call[];            // Array of calls to execute
  capabilities?: object;    // Optional capabilities
}

interface Call {
  to: string;      // Target contract address
  data?: string;   // Encoded call data (optional)
  value?: string;  // ETH value to send (hex, optional)
}
```

#### Request Example

```bash
curl -X POST http://localhost:8323 \
  -H "Content-Type: application/json" \
  -d '{
    "method": "wallet_prepareCalls",
    "params": {
      "version": "1.0",
      "chainId": "0x7a69",
      "from": "0x742d35Cc6634C0532925a3b8D6Cb9E15d47b2644",
      "calls": [
        {
          "to": "0xA0b86a33E6411B10FdF6FFf01d7F37e6E8C29D21",
          "data": "0xa9059cbb000000000000000000000000742d35cc6634c0532925a3b8d6cb9e15d47b264400000000000000000000000000000000000000000000000000000000000f4240"
        }
      ]
    },
    "id": 1,
    "jsonrpc": "2.0"
  }'
```

#### Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "version": "1.0",
    "chainId": "0x7a69",
    "context": "quotes",
    "calls": [
      {
        "to": "0xA0b86a33E6411B10FdF6FFf01d7F37e6E8C29D21",
        "data": "0xa9059cbb000000000000000000000000742d35cc6634c0532925a3b8d6cb9e15d47b264400000000000000000000000000000000000000000000000000000000000f4240"
      }
    ],
    "expiry": 1640995200,
    "quotes": {
      "0x0000000000000000000000000000000000000000": {
        "maxFeePerGas": "0x174876e800",
        "maxPriorityFeePerGas": "0x3b9aca00",
        "gas": "0x5208"
      }
    }
  }
}
```

### `wallet_sendPreparedCalls`

Submit signed intent for execution.

**Method**: `wallet_sendPreparedCalls`  
**Parameters**: `SendPreparedCallsParameters`

#### Parameters

```typescript
interface SendPreparedCallsParameters {
  version: string;
  chainId: string;
  from: string;
  calls: Call[];
  signature: string;        // User signature
  context: object;          // Context from prepareCalls response
}
```

#### Request Example

```bash
curl -X POST http://localhost:8323 \
  -H "Content-Type: application/json" \
  -d '{
    "method": "wallet_sendPreparedCalls",
    "params": {
      "version": "1.0",
      "chainId": "0x7a69",
      "from": "0x742d35Cc6634C0532925a3b8D6Cb9E15d47b2644",
      "calls": [...],
      "signature": "0x...",
      "context": {...}
    },
    "id": 1,
    "jsonrpc": "2.0"
  }'
```

#### Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "bundleId": "0x1234567890abcdef..."
  }
}
```

### `wallet_getCallsStatus`

Query execution status of submitted calls.

**Method**: `wallet_getCallsStatus`  
**Parameters**: `{ bundleId: string }`

#### Request Example

```bash
curl -X POST http://localhost:8323 \
  -H "Content-Type: application/json" \
  -d '{
    "method": "wallet_getCallsStatus",
    "params": {
      "bundleId": "0x1234567890abcdef..."
    },
    "id": 1,
    "jsonrpc": "2.0"
  }'
```

#### Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "status": "CONFIRMED",
    "receipts": [
      {
        "logs": [],
        "status": "0x1",
        "blockHash": "0x...",
        "blockNumber": "0x123",
        "gasUsed": "0x5208",
        "transactionHash": "0x..."
      }
    ]
  }
}
```

## Account Namespace

Account management endpoints (requires email configuration).

### `account_requestVerification`

Request email verification for account setup.

**Method**: `account_requestVerification`  
**Parameters**: `{ email: string }`

### `account_verifyEmail`

Verify email with code.

**Method**: `account_verifyEmail`  
**Parameters**: `{ email: string, code: string }`

### `account_getProfile`

Get account profile information.

**Method**: `account_getProfile`  
**Parameters**: `{ address: string }`

## Onramp Namespace

Fiat onramp integration endpoints.

### `onramp_getQuote`

Get fiat-to-crypto quote.

**Method**: `onramp_getQuote`  
**Parameters**: `OnrampQuoteRequest`

### `onramp_createOrder`

Create fiat purchase order.

**Method**: `onramp_createOrder`  
**Parameters**: `OnrampOrderRequest`

## Health Endpoints

Non-JSON-RPC endpoints for monitoring.

### `GET /health`

Basic health check.

```bash
curl http://localhost:8323/health
```

Response: `200 OK` if healthy

### `GET /health/database`

Database connectivity check.

### `GET /health/providers`

Blockchain provider connectivity check.

### `GET /health/queues`

Transaction queue status check.

## Error Handling

### Error Response Format

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32602,
    "message": "Invalid params",
    "data": {
      "details": "Missing required field: chainId"
    }
  }
}
```

### Common Error Codes

| Code | Message | Description |
|------|---------|-------------|
| -32700 | Parse error | Invalid JSON |
| -32600 | Invalid Request | Invalid JSON-RPC request |
| -32601 | Method not found | Unknown method |
| -32602 | Invalid params | Invalid parameters |
| -32603 | Internal error | Server error |
| -32000 | Relay error | Relay-specific error |

### Relay-Specific Errors

| Code | Type | Description |
|------|------|-------------|
| 1001 | UnsupportedChain | Chain not supported by relay |
| 1002 | InsufficientFunds | Account lacks required funds |
| 1003 | InvalidIntent | Intent validation failed |
| 1004 | QuoteExpired | Quote has expired |
| 1005 | SimulationFailed | Transaction simulation failed |

## Rate Limiting

The relay implements rate limiting to prevent abuse:

- **Per IP**: 100 requests per minute
- **Per Account**: 50 transactions per minute  
- **Burst**: 10 requests per second

Rate limit headers are included in responses:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
```

## WebSocket Support

Real-time updates via WebSocket connection.

### Connection

```javascript
const ws = new WebSocket('ws://localhost:8323');

ws.onopen = () => {
  // Subscribe to bundle updates
  ws.send(JSON.stringify({
    method: 'subscribe',
    params: {
      type: 'bundle_status',
      bundleId: '0x...'
    }
  }));
};

ws.onmessage = (event) => {
  const update = JSON.parse(event.data);
  console.log('Bundle status:', update);
};
```

### Subscription Types

- `bundle_status`: Bundle execution updates
- `transaction_status`: Individual transaction updates
- `account_activity`: Account-specific activity

## Client Libraries

### JavaScript/TypeScript

```javascript
import { createWalletClient, http } from 'viem';

const client = createWalletClient({
  transport: http('http://localhost:8323')
});

// Prepare calls
const prepared = await client.request({
  method: 'wallet_prepareCalls',
  params: {
    version: '1.0',
    chainId: '0x7a69',
    from: account.address,
    calls: [...]
  }
});
```

### Python

```python
import requests

class RelayClient:
    def __init__(self, url="http://localhost:8323"):
        self.url = url
        self.session = requests.Session()
    
    def prepare_calls(self, version, chain_id, from_addr, calls):
        payload = {
            "method": "wallet_prepareCalls",
            "params": {
                "version": version,
                "chainId": chain_id,
                "from": from_addr,
                "calls": calls
            },
            "id": 1,
            "jsonrpc": "2.0"
        }
        
        response = self.session.post(
            self.url,
            json=payload,
            headers={"Content-Type": "application/json"}
        )
        
        return response.json()
```

### Go

```go
package main

import (
    "bytes"
    "encoding/json"
    "net/http"
)

type RelayClient struct {
    URL string
}

func (r *RelayClient) PrepareCalls(req PrepareCallsRequest) (*PrepareCallsResponse, error) {
    payload := map[string]interface{}{
        "method":  "wallet_prepareCalls",
        "params":  req,
        "id":      1,
        "jsonrpc": "2.0",
    }
    
    jsonData, _ := json.Marshal(payload)
    resp, err := http.Post(r.URL, "application/json", bytes.NewBuffer(jsonData))
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var result PrepareCallsResponse
    json.NewDecoder(resp.Body).Decode(&result)
    return &result, nil
}
```

## Testing with cURL

### Complete Flow Example

```bash
# 1. Check relay capabilities
curl -X POST http://localhost:8323 \
  -H "Content-Type: application/json" \
  -d '{
    "method": "wallet_getCapabilities",
    "params": {},
    "id": 1,
    "jsonrpc": "2.0"
  }'

# 2. Prepare calls
curl -X POST http://localhost:8323 \
  -H "Content-Type: application/json" \
  -d '{
    "method": "wallet_prepareCalls",
    "params": {
      "version": "1.0",
      "chainId": "0x7a69",
      "from": "0x...",
      "calls": [...]
    },
    "id": 2,
    "jsonrpc": "2.0"
  }'

# 3. Send prepared calls (with signature)
curl -X POST http://localhost:8323 \
  -H "Content-Type: application/json" \
  -d '{
    "method": "wallet_sendPreparedCalls",
    "params": {
      "version": "1.0",
      "chainId": "0x7a69",
      "from": "0x...",
      "calls": [...],
      "signature": "0x...",
      "context": {...}
    },
    "id": 3,
    "jsonrpc": "2.0"
  }'

# 4. Check status
curl -X POST http://localhost:8323 \
  -H "Content-Type: application/json" \
  -d '{
    "method": "wallet_getCallsStatus",
    "params": {
      "bundleId": "0x..."
    },
    "id": 4,
    "jsonrpc": "2.0"
  }'
```

## Performance Guidelines

### Request Optimization

- **Batch requests**: Use single connection for multiple calls
- **Reuse connections**: Keep HTTP connections alive
- **Compress payloads**: Use gzip compression for large requests

### Response Handling

- **Parse errors**: Always check for error responses
- **Handle retries**: Implement exponential backoff for failures
- **Monitor rate limits**: Track rate limit headers

---

## Related Documentation

- **[RPC Endpoints](../architecture/rpc-endpoints.md)** - Implementation details
- **[Error Handling](../troubleshooting/common-issues.md)** - Troubleshooting guide
- **[Getting Started](../development/getting-started.md)** - Development setup