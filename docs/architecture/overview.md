# Relay Architecture Overview

The Ithaca Relay is a transparent cross-chain transaction router for EIP-7702 accounts that provides fee abstraction and intent-based execution.

## Porto Ecosystem Architecture

The relay operates within the broader Porto ecosystem, which consists of three main layers:

```mermaid
graph TB
    subgraph "Client Layer"
        App[dApp/Frontend]
        SDK[Porto SDK]
        Wagmi[Wagmi Integration]
        Browser[Browser Extension]
    end
    
    subgraph "Relay Layer (This Repository)"
        RPC[RPC Server]
        Quote[Quote Engine]
        TX[Transaction Processor]
        Monitor[Status Monitor]
        Cross[Cross-Chain Coordinator]
    end
    
    subgraph "Blockchain Layer"
        ORCH[Orchestrator Contract]
        ACC[Account Implementation]
        SIM[Simulator Contract]
        ESC[Escrow Contract]
        FUND[Funder Contract]
    end
    
    subgraph "Infrastructure"
        DB[(PostgreSQL)]
        METRICS[Prometheus]
        LZ[LayerZero Network]
        ORACLE[Price Oracles]
    end
    
    App --> SDK
    SDK --> RPC
    RPC --> Quote
    RPC --> TX
    TX --> Monitor
    TX --> Cross
    
    Quote --> ORCH
    TX --> ORCH
    Cross --> ESC
    Cross --> FUND
    
    TX --> DB
    Quote --> ORACLE
    Cross --> LZ
    
    RPC --> METRICS
```

## Design Principles

### 1. Intent-Driven Execution
Users express **what** they want to achieve, not **how** to achieve it. The relay handles execution details.

### 2. Trustless Operation  
- **Cryptographic Authorization**: Users sign specific intent digests
- **Atomic Execution**: Smart contracts enforce all-or-nothing execution
- **Non-Custodial**: Relay cannot access user funds directly

### 3. Cross-Chain Native Design
- **Unified Account Model**: Same account works across all chains
- **Atomic Cross-Chain**: Either all chains succeed or all fail
- **Intelligent Fund Sourcing**: Automatically routes liquidity

## Intent Lifecycle Phases

### Phase 1: Preparation
```mermaid
sequenceDiagram
    participant User
    participant SDK
    participant Relay
    participant Simulator
    
    User->>SDK: sendCalls({ calls, feeToken })
    SDK->>Relay: wallet_prepareCalls
    Relay->>Simulator: simulate execution
    Simulator-->>Relay: gas estimate + asset diffs
    Relay->>Relay: generate quote
    Relay-->>SDK: signed quote + digest
    SDK-->>User: request signature
```

### Phase 2: Execution
```mermaid
sequenceDiagram
    participant User
    participant SDK
    participant Relay
    participant Orchestrator
    participant Chain
    
    User->>SDK: sign(digest)
    SDK->>Relay: wallet_sendPreparedCalls
    Relay->>Relay: verify signatures
    Relay->>Chain: broadcast transaction
    Chain->>Orchestrator: execute intent
    Orchestrator-->>Chain: emit events
    Relay-->>SDK: bundle_id
```

### Phase 3: Monitoring
```mermaid
sequenceDiagram
    participant SDK
    participant Relay
    participant Chain
    
    loop Status Polling
        SDK->>Relay: wallet_getCallsStatus
        Relay->>Chain: check transaction status
        Chain-->>Relay: receipt/status
        Relay-->>SDK: execution status
    end
```

## Detailed Data Flow

The complete intent processing follows a 15-step data flow from SDK creation to final confirmation:

```mermaid
graph TB
    subgraph "User/SDK Layer"
        U[1. User Creates Intent]
        S[2. SDK Validates & Serializes]
    end
    
    subgraph "Relay RPC Layer"
        P[3. wallet_prepareCalls]
        SE[10. wallet_sendPreparedCalls]
        GS[15. wallet_getCallsStatus]
    end
    
    subgraph "Relay Core Engine"
        V[4. Request Validation]
        ST[5. Strategy Determination]
        SIM[6. Simulation Engine]
        O[7. Price Oracle]
        Q[8. Quote Builder]
        VER[11. Signature Verification]
        T[12. Transaction Service] 
        M[14. Monitor Service]
    end
    
    subgraph "Blockchain Layer"
        BC[13. Smart Contracts]
        TX[Transaction Pool]
    end
    
    subgraph "User Action"
        SIGN[9. User Signature]
    end
    
    U --> S
    S --> P
    P --> V
    V --> ST
    ST --> SIM
    SIM --> O
    O --> Q
    Q --> SIGN
    SIGN --> SE
    SE --> VER
    VER --> T
    T --> TX
    TX --> BC
    BC --> M
    M --> GS
```

### Step-by-Step Implementation Details

#### Steps 1-2: Intent Creation and SDK Processing
**Client Layer Processing**:
- User creates high-level intent object
- SDK validates parameters and serializes to JSON-RPC

#### Steps 3-8: Preparation Phase (`wallet_prepareCalls`)

**Step 3**: RPC Endpoint Entry (**Implementation**: `src/rpc/relay.rs:1697-1702`)

**Step 4**: Request Validation (**Implementation**: `src/rpc/relay.rs:901-915`)
- Call structure validation  
- Chain support verification
- Account delegation checking

**Step 5**: Strategy Determination (**Implementation**: `src/rpc/relay.rs:1134-1200`)
- Single-chain vs multichain analysis
- Fund sourcing across chains (**Implementation**: `src/rpc/relay.rs:1697-1850`)
- Execution plan generation

**Step 6**: Simulation Execution (**Implementation**: `src/types/orchestrator.rs:198-284`)
- Off-chain contract simulation
- Asset diff calculation (**Implementation**: `src/asset.rs:186-221`)
- Gas usage prediction

**Step 7**: Price Oracle Consultation (**Implementation**: `src/price/oracle.rs:65-90`)
- Token price fetching from CoinGecko
- ETH-denominated conversion
- Fee calculation in payment token

**Step 8**: Quote Generation (**Implementation**: `src/rpc/relay.rs:400-450`)
- Quote signing with relay's private key
- EIP-712 digest calculation (**Implementation**: `src/types/intent.rs:459-485`)
- TTL and expiration setting

#### Step 9: User Signature
**Client-Side Action**:
- User reviews quote and asset diffs
- Signs EIP-712 digest with wallet (MetaMask, etc.)

#### Steps 10-12: Execution Phase (`wallet_sendPreparedCalls`)

**Step 10**: RPC Endpoint Entry (**Implementation**: `src/rpc/relay.rs:1775-1794`)

**Step 11**: Signature Verification (**Implementation**: `src/rpc/relay.rs:451-491`) 
- Quote expiration checking
- Quote signature validation
- User signature assembly

**Step 12**: Transaction Broadcasting (**Implementation**: `src/transactions/signer.rs:142-180`)
- Transaction signing with relay's key
- Network broadcast via provider
- Transaction service coordination (**Implementation**: `src/transactions/service.rs:85-120`)

#### Step 13: Blockchain Execution
**Smart Contract Processing**:
- Orchestrator validates intent and signatures
- Processes payments and executes calls atomically
- Emits execution events for monitoring

#### Steps 14-15: Monitoring Phase

**Step 14**: Status Monitoring (**Implementation**: `src/transactions/monitor.rs:65-120`)
- Transaction confirmation tracking
- Database status updates (**Implementation**: `src/storage/pg.rs:150-200`)
- Event log parsing

**Step 15**: Status Retrieval (**Implementation**: `src/rpc/relay.rs:1878-1943`)
- Bundle status aggregation
- Receipt processing
- Final status determination

## High-Level Architecture

```mermaid
graph TB
    subgraph "External Interfaces"
        SDK[Porto SDK]
        CLI[CLI Tools]
        WEB[Web Clients]
    end
    
    subgraph "Relay Core"
        RPC[RPC Server<br/>JSON-RPC API]
        TX[Transaction Service<br/>Processing Pipeline]
        ORACLE[Price Oracle<br/>Fee Conversion]
        STORAGE[Storage Layer<br/>PostgreSQL]
    end
    
    subgraph "Blockchain Layer"
        ORCH[Orchestrator Contract]
        DEL[Delegation Proxy]
        ERC20[Fee Tokens]
        LZ[LayerZero<br/>Cross-chain]
    end
    
    SDK --> RPC
    CLI --> RPC
    WEB --> RPC
    
    RPC --> TX
    RPC --> ORACLE
    RPC --> STORAGE
    
    TX --> ORCH
    TX --> DEL
    TX --> ERC20
    TX --> LZ
    
    ORACLE --> STORAGE
    TX --> STORAGE
```

## Core Components

### 1. RPC Server (`src/rpc/`)

The JSON-RPC server provides the main interface for clients to interact with the relay.

**Key modules**:
- **`relay.rs`** (**Lines 1-2000+**) - Main relay endpoints (`wallet_prepareCalls`, `wallet_sendPreparedCalls`, `wallet_getCallsStatus`)
- **`account.rs`** (**Lines 1-500+**) - Account management and delegation
- **`onramp.rs`** (**Lines 1-300+**) - Onramp integration

**Server setup** (**Implementation**: `src/spawn.rs:253-280`):
```rust
// Creates JSON-RPC server with wallet namespace
let mut rpc = relay.into_rpc();
```

**Request handling pattern**:
1. **Validation** - Request structure and parameters
2. **Processing** - Business logic execution
3. **Response** - Structured JSON-RPC response

### 2. Transaction Service (`src/transactions/`)

Handles the complete transaction lifecycle from intent preparation to blockchain confirmation.

**Core components**:
- **`service.rs`** (**Lines 85-120**) - Main transaction orchestration service
- **`signer.rs`** (**Lines 142-300**) - Transaction signing and broadcasting
- **`monitor.rs`** (**Lines 45-200**) - Transaction status monitoring
- **`fees.rs`** (**Lines 25-150**) - Fee estimation and calculation

**Transaction pipeline**:
1. **Queue** (**Implementation**: `src/transactions/service.rs:150-180`) - Per-EOA nonce ordering
2. **Sign** (**Implementation**: `src/transactions/signer.rs:201-240`) - Cryptographic signing
3. **Broadcast** (**Implementation**: `src/transactions/signer.rs:142-180`) - Network submission
4. **Monitor** (**Implementation**: `src/transactions/monitor.rs:65-120`) - Confirmation tracking

### 3. Storage Layer (`src/storage/`)

Provides persistent storage with PostgreSQL backend and in-memory testing support.

**Storage abstractions**:
- **`api.rs`** (**Lines 15-200**) - Storage trait definitions
- **`pg.rs`** (**Lines 45-800**) - PostgreSQL implementation
- **`memory.rs`** (**Lines 25-400**) - In-memory implementation for tests

**Key storage entities**:
- **Transactions** (**Schema**: `migrations/0004_multiple_transactions.sql`)
- **Bundles** (**Schema**: `migrations/0013_pending_bundles.sql`) 
- **Accounts** (**Schema**: `migrations/0006_entrypoint.sql`)
- **Intents** (**Schema**: `migrations/0008_intent.sql`)

**Database migrations** (**Location**: `migrations/`) are applied automatically on startup.

### 4. Price Oracle (`src/price/`)

Fetches token prices for fee conversion and payment processing.

**Components**:
- **`oracle.rs`** (**Lines 65-150**) - Main oracle coordination
- **`fetchers/coingecko.rs`** (**Lines 25-200**) - CoinGecko price fetching
- **`metrics.rs`** (**Lines 15-100**) - Price oracle metrics

**Price flow**:
1. **Fetch** - External API calls (CoinGecko, etc.)
2. **Cache** - In-memory price caching with TTL
3. **Convert** - ETH-denominated price conversion

### 5. Cross-Chain Operations (`src/interop/`)

Handles multichain intent execution with atomic settlement guarantees.

**Key components**:
- **`escrow.rs`** (**Lines 45-200**) - Fund locking and unlocking
- **`settler/`** - Settlement message processing
  - **`layerzero/`** (**Lines 25-300**) - LayerZero message handling
  - **`processor.rs`** (**Lines 40-250**) - Settlement state machine
- **`refund/`** - Refund processing for failed operations

**Bundle state machine** (**Implementation**: `src/transactions/interop.rs:85-200`):

See [Bundle State Machine Diagram](../diagrams/bundle_state_machine.svg) for visual representation.

**States** (**Definition**: `src/transactions/interop.rs:25-45`):
- `Init` → `LiquidityLocked` → `SourceQueued` → `SourceConfirmed` → `DestinationQueued` → `DestinationConfirmed` → `SettlementsQueued` → `Done`

## Type System (`src/types/`)

The relay uses a comprehensive type system for type safety and clear interfaces.

**Core domain types**:
- **`intent.rs`** (**Lines 25-500**) - Intent structures and validation
- **`quote.rs`** (**Lines 15-200**) - Quote generation and signing
- **`call.rs`** (**Lines 10-150**) - Call execution types
- **`account.rs`** (**Lines 20-300**) - Account management types

**RPC types** (**Location**: `src/types/rpc/`):
- **`calls.rs`** (**Lines 45-200**) - Request/response structures
- **`capabilities.rs`** (**Lines 15-100**) - Client capability negotiation

**Contract interfaces** (**Location**: `src/types/`):
- **`orchestrator.rs`** (**Lines 50-400**) - Orchestrator contract interface
- **`simulator.rs`** (**Lines 25-150**) - Simulation contract interface

## Configuration System (`src/config.rs`)

Supports YAML configuration with CLI overrides.

**Configuration structure** (**Implementation**: `src/config.rs:45-200`):
- **Server** - RPC server settings (address, port, CORS)
- **Chain** - Blockchain endpoints and fee tokens
- **Quote** - Quote TTL and gas estimation settings
- **Storage** - Database connection parameters
- **Oracle** - Price fetching configuration

**Configuration precedence**:
1. CLI arguments (highest priority)
2. YAML configuration file
3. Default values (lowest priority)

## Error Handling (`src/error/`)

Comprehensive error handling with context and structured error types.

**Error hierarchy** (**Implementation**: `src/error/mod.rs:15-100`):
- **`RelayError`** - Top-level error type
- **Module errors** - Specific error types per module
  - `QuoteError` (**Implementation**: `src/error/quote.rs`)
  - `IntentError` (**Implementation**: `src/error/intent.rs`)
  - `StorageError` (**Implementation**: `src/error/storage.rs`)

**Error handling patterns**:
- Use `eyre` for error context
- Structured error responses for RPC
- Metrics collection on errors

## Metrics and Observability (`src/metrics/`)

Built-in Prometheus metrics and OpenTelemetry tracing.

**Metrics collection**:
- **`transport.rs`** (**Lines 25-150**) - HTTP metrics transport
- **`periodic/`** - Background metric collection jobs
  - **`balance.rs`** (**Lines 15-80**) - Account balance monitoring
  - **`latency.rs`** (**Lines 20-100**) - Request latency tracking

**Tracing** (**Integration**: `src/otlp.rs:25-100`):
- Request tracing with correlation IDs
- Database query tracing
- Cross-chain operation tracking

## Development Patterns

### Async Architecture

The relay is built on Tokio async runtime with message-passing between components.

**Service pattern** (**Example**: `src/transactions/service.rs:45-85`):
- Services expose handle types for communication
- Background tasks process messages
- Clean shutdown with graceful termination

### Database Integration

Uses SQLx for compile-time checked SQL queries.

**Query pattern** (**Example**: `src/storage/pg.rs:150-180`):
```rust
// Compile-time checked SQL
let result = sqlx::query!("SELECT * FROM transactions WHERE id = $1", id)
    .fetch_one(&self.pool)
    .await?;
```

### Testing Architecture

**E2E testing framework** (**Implementation**: `tests/e2e/environment.rs:45-150`):
- Standardized test environment setup
- Contract deployment and funding
- Relay service integration
- Multi-chain test support

## Security Considerations

### Private Key Management

**Signer architecture** (**Implementation**: `src/signers/`):
- **`p256.rs`** - P256 elliptic curve signing
- **`webauthn.rs`** - WebAuthn hardware signing
- **`dyn.rs`** - Dynamic signer selection

### Transaction Validation

**Validation layers**:
1. **RPC validation** - Request structure and parameters
2. **Intent validation** (**Implementation**: `src/types/intent.rs:200-300`) - Business logic validation
3. **Contract validation** - On-chain execution validation

### Access Control

**Permission system** (**Implementation**: `src/types/rpc/permission.rs:15-80`):
- Account delegation verification
- Intent authorization checking
- Rate limiting and quota management

## Performance Optimizations

### Connection Pooling

**Database connections** (**Implementation**: `src/storage/pg.rs:45-80`):
- PostgreSQL connection pooling with SQLx
- Configurable pool size and timeouts

**RPC connections** (**Implementation**: `src/provider.rs:25-100`):
- HTTP/WebSocket provider pooling
- Automatic failover between endpoints

### Caching Strategies

**Price caching** (**Implementation**: `src/price/oracle.rs:85-120`):
- In-memory price cache with TTL
- Fallback to constant rates

**Simulation caching** - State override reuse for gas estimation

### Concurrent Processing

**Transaction processing** (**Implementation**: `src/transactions/service.rs:120-180`):
- Per-chain transaction queues
- Parallel processing with nonce ordering
- Load balancing across signers

---

## Related Documentation

- **[RPC Endpoints](rpc-endpoints.md)** - Detailed RPC implementation
- **[Transaction Pipeline](transaction-pipeline.md)** - End-to-end transaction flow
- **[Cross-Chain Operations](cross-chain.md)** - Multichain implementation details
- **[Storage Layer](storage-layer.md)** - Database schema and operations

---

💡 **Development Tip**: Use `src/lib.rs` as the main entry point to understand module organization and dependencies.