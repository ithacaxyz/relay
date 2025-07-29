# Debugging Guide

This guide covers debugging techniques, tools, and best practices for developing and troubleshooting the Ithaca Relay, with special focus on e2e testing environments and blockchain interactions.

## E2E Test Debugging

### Multiple Anvil Instance Setup

The e2e tests spin up multiple Anvil instances to simulate multi-chain environments. Understanding this setup is crucial for debugging cross-chain functionality.

**Test environment architecture** (**Implementation**: `tests/e2e/environment.rs`):
```rust
// E2E tests create multiple chains
// Chain 0: Usually Ethereum mainnet fork or local
// Chain 1: Arbitrum or local testnet
// Chain 2: Polygon or another L2
```

### Anvil Debugging with Traces

**Enable execution traces** for detailed transaction debugging:

```bash
# Start Anvil with trace printing
anvil --print-traces --port 8545 --chain-id 1

# For multi-chain setup
anvil --print-traces --port 8545 --chain-id 1 &  # Chain 0
anvil --print-traces --port 8546 --chain-id 42161 &  # Chain 1  
anvil --print-traces --port 8547 --chain-id 137 &   # Chain 2
```

**Using external Anvil instances in tests**:
```bash
# Point tests to external Anvil instances
TEST_EXTERNAL_ANVIL_0="http://localhost:8545" \
TEST_EXTERNAL_ANVIL_1="http://localhost:8546" \
TEST_EXTERNAL_ANVIL_2="http://localhost:8547" \
cargo test test_multichain_intent
```

### Trace Output Analysis

**Example trace output from `anvil --print-traces`**:
```
eth_call
  Executor::execute()
    ├─ emit IntentStarted(intentId: 0x123...)
    ├─ SLOAD [sender_nonces] → 42
    ├─ CALL TokenTransfer::transfer(to: 0xabc..., amount: 1000000)
    │   ├─ SLOAD [balances][0xdef...] → 5000000
    │   ├─ SSTORE [balances][0xdef...] ← 4000000
    │   ├─ SSTORE [balances][0xabc...] ← 1000000
    │   └─ emit Transfer(from: 0xdef..., to: 0xabc..., value: 1000000)
    ├─ SSTORE [sender_nonces] ← 43
    └─ emit IntentExecuted(intentId: 0x123..., success: true)
```

**Key debugging information from traces**:
- **Storage operations**: `SLOAD`/`SSTORE` show state changes
- **External calls**: `CALL`/`STATICCALL` to other contracts
- **Events**: `emit` statements show contract events
- **Gas usage**: Track gas consumption per operation
- **Revert reasons**: Clear error messages when transactions fail

### E2E Test Configuration

**Environment variables for debugging**:
```bash
# Use external Anvil instances
export TEST_EXTERNAL_ANVIL_0="http://localhost:8545"
export TEST_EXTERNAL_ANVIL_1="http://localhost:8546" 
export TEST_EXTERNAL_ANVIL_2="http://localhost:8547"

# Fork from specific block for consistency
export TEST_FORK_BLOCK_NUMBER=18000000

# Use specific test account
export TEST_EOA_PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# Point to contract artifacts
export TEST_CONTRACTS="$(pwd)/tests/account/out"

# Enable verbose logging
export RUST_LOG=debug
```

**Running tests with debugging**:
```bash
# Run single test with detailed output
cargo test test_multichain_usdt_transfer -- --nocapture

# Run with tracing enabled
RUST_LOG=relay=debug,tests=debug cargo test e2e -- --nocapture

# Run specific chain combination
TEST_EXTERNAL_ANVIL_0="http://localhost:8545" \
TEST_EXTERNAL_ANVIL_2="http://localhost:8547" \
cargo test test_cross_chain_funding
```

## Frontend Development Debugging

### Docker Compose Setup

The frontend team uses Docker Compose for local development and integration testing, which provides a consistent environment for debugging new relay features.

**Docker Compose workflow**:
```bash
# Start the development environment
docker-compose up -d

# View logs from all services
docker-compose logs -f

# View specific service logs
docker-compose logs -f relay
docker-compose logs -f frontend

# Execute commands in running containers
docker-compose exec relay bash
docker-compose exec frontend npm run debug
```

**Integration testing with Docker Compose**:
- Provides isolated networking environment for multi-service debugging
- Enables consistent testing across different development machines
- Facilitates debugging of relay-frontend communication patterns

### Stress Testing Scripts

The team maintains stress testing scripts to validate relay performance under load conditions.

**Running stress tests**:
```bash
# Execute stress testing suite
./scripts/stress-test.sh

# Run specific stress test scenarios
./scripts/stress-test.sh --scenario heavy-load
./scripts/stress-test.sh --scenario multi-chain
./scripts/stress-test.sh --scenario concurrent-intents

# Monitor system resources during stress tests
docker stats
htop
```

**Common stress testing issues**:
- **Token-related errors**: Often occur under high transaction volume
- **Contract state conflicts**: Multiple concurrent operations on same contracts
- **Resource exhaustion**: Connection pool limits, memory usage spikes

## Cast CLI Integration

[Cast](https://book.getfoundry.sh/cast/) is an essential tool for interacting with blockchain nodes and debugging contract state.

### Cast Limitations and Workarounds

**Known Cast limitations**:
- `cast call --trace` sometimes fails on `eth_call` and `estimate_gas` operations
- Cannot debug complex multi-step transactions that fail during gas estimation
- Limited support for debugging failed state changes in complex contract interactions

**Workarounds for Cast limitations**:
```bash
# When cast --trace fails, use Anvil traces instead
anvil --print-traces --port 8545 &

# For failed eth_call operations, use direct RPC calls
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_call",
    "params": [{"to": "'$CONTRACT'", "data": "'$CALLDATA'"}, "latest"],
    "id": 1
  }' | jq

# Debug transaction simulation with custom gas limit
cast call $CONTRACT "method()" $PARAMS \
  --gas-limit 1000000 \
  --from $CALLER \
  --rpc-url http://localhost:8545
```

**Contributing Cast improvements**:
- When encountering Cast limitations, consider contributing fixes to the Foundry team
- Open issues with reproduction steps and expected behavior
- Stay focused on relay development while identifying opportunities for cross-functional contribution

### Basic Cast Commands

**Network interaction**:
```bash
# Check connection to Anvil
cast chain-id --rpc-url http://localhost:8545

# Get latest block
cast block-number --rpc-url http://localhost:8545

# Check account balance
cast balance 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 --rpc-url http://localhost:8545
```

**Contract interaction**:
```bash
# Read contract state
cast call $ORCHESTRATOR_ADDRESS "getNonce(address)" $USER_ADDRESS --rpc-url http://localhost:8545

# Send transaction
cast send $ERC20_ADDRESS "transfer(address,uint256)" $RECIPIENT $AMOUNT \
  --private-key $PRIVATE_KEY \
  --rpc-url http://localhost:8545

# Get transaction receipt
cast receipt $TX_HASH --rpc-url http://localhost:8545
```

### MESC Configuration

[MESC](https://github.com/paradigmxyz/mesc) provides a configuration system for managing multiple RPC endpoints.

**Installation**:
```bash
# Install MESC
cargo install mesc

# Initialize configuration
mesc init
```

**Configuration example** (`~/.mesc/mesc.json`):
```json
{
  "mesc_version": "0.1.0",
  "default_endpoint": "local_anvil",
  "endpoints": {
    "local_anvil": {
      "name": "local_anvil", 
      "url": "http://localhost:8545",
      "chain_id": 1
    },
    "local_arb": {
      "name": "local_arb",
      "url": "http://localhost:8546", 
      "chain_id": 42161
    },
    "local_polygon": {
      "name": "local_polygon",
      "url": "http://localhost:8547",
      "chain_id": 137
    },
    "mainnet_fork": {
      "name": "mainnet_fork",
      "url": "http://localhost:8545",
      "chain_id": 1
    }
  },
  "profiles": {
    "test": {
      "default_endpoint": "local_anvil",
      "endpoints": {
        "1": "local_anvil",
        "42161": "local_arb", 
        "137": "local_polygon"
      }
    }
  }
}
```

**Using MESC with Cast**:
```bash
# Use named endpoint
cast balance $ADDRESS --endpoint local_anvil

# Use profile
cast call $CONTRACT "method()" --profile test --chain 42161

# List configured endpoints
mesc ls
```

### Contract Debugging Patterns

**Reading contract state**:
```bash
# Check orchestrator contract state
ORCHESTRATOR="0x..."
USER_ADDRESS="0x..."

# Get user nonce
cast call $ORCHESTRATOR "getNonce(address)" $USER_ADDRESS

# Check delegation status  
cast call $ORCHESTRATOR "isDelegated(address)" $USER_ADDRESS

# Read intent execution status
INTENT_ID="0x..."
cast call $ORCHESTRATOR "getIntentStatus(bytes32)" $INTENT_ID
```

**Debugging failed transactions**:
```bash
# Get detailed transaction info
cast tx $TX_HASH --rpc-url http://localhost:8545

# Analyze revert reason
cast receipt $TX_HASH --rpc-url http://localhost:8545 | jq '.logs'

# Simulate transaction to see revert
cast call $CONTRACT "failingMethod()" $PARAMS \
  --from $SENDER \
  --rpc-url http://localhost:8545
```

## Relay Service Debugging

### Logging Configuration

**Enable comprehensive logging**:
```bash
# Debug level for all components
export RUST_LOG=debug

# Specific component logging
export RUST_LOG=relay::rpc=debug,relay::transactions=trace

# JSON structured logging
export RUST_LOG_FORMAT=json

# Log to file
export RUST_LOG_FILE=/tmp/relay-debug.log
```

**Key log patterns to watch**:
```bash
# Intent preparation
grep "prepare_calls" relay.log

# Transaction submission
grep "send_prepared_calls" relay.log

# Cross-chain coordination
grep "multichain" relay.log

# Price oracle updates
grep "oracle.*price" relay.log

# Database queries
grep "sqlx" relay.log
```

### RPC Debugging

**Test RPC endpoints directly**:
```bash
# Prepare calls
curl -X POST http://localhost:8323 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "wallet_prepareCalls",
    "params": {
      "calls": [{"to": "0x...", "data": "0x...", "value": "0x0"}],
      "chainId": 1,
      "from": "0x...",
      "capabilities": {}
    },
    "id": 1
  }' | jq

# Check calls status
curl -X POST http://localhost:8323 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0", 
    "method": "wallet_getCallsStatus",
    "params": ["0x..."],
    "id": 1
  }' | jq
```

**WebSocket debugging**:
```bash
# Connect to WebSocket endpoint
websocat ws://localhost:8323

# Send JSON-RPC over WebSocket
{"jsonrpc":"2.0","method":"wallet_prepareCalls","params":{...},"id":1}
```

### Database Debugging

**Direct database inspection**:
```bash
# Connect to PostgreSQL
psql $DATABASE_URL

# Check recent transactions
SELECT id, chain_id, status, created_at 
FROM transactions 
ORDER BY created_at DESC 
LIMIT 10;

# Check bundle status
SELECT bundle_id, status, chain_count, created_at
FROM bundles 
WHERE created_at > NOW() - INTERVAL '1 hour';

# Check account nonces
SELECT account, chain_id, nonce, updated_at
FROM account_nonces
ORDER BY updated_at DESC;
```

**Database connection debugging**:
```bash
# Test database connectivity
pg_isready -h localhost -p 5432

# Check connection pool status
curl http://localhost:8323/health | jq '.database'

# Monitor active connections
SELECT count(*) as active_connections 
FROM pg_stat_activity 
WHERE state = 'active';
```

## Performance Analysis

### Memory Profiling

**Using Valgrind**:
```bash
# Install valgrind
sudo apt install valgrind

# Build with debugging symbols
cargo build --profile profiling

# Run with memory checking
valgrind --tool=memcheck \
  --leak-check=full \
  --show-leak-kinds=all \
  target/profiling/relay
```

**Using heaptrack**:
```bash
# Install heaptrack
sudo apt install heaptrack

# Profile memory usage
heaptrack target/release/relay

# Analyze results
heaptrack_gui heaptrack.relay.123.gz
```

### CPU Profiling

**Using perf**:
```bash
# Install perf
sudo apt install linux-perf

# Record performance data
perf record -g target/release/relay

# Generate flame graph
perf script | ./flamegraph.pl > relay-flamegraph.svg
```

**Using cargo flamegraph**:
```bash
# Install flamegraph
cargo install flamegraph

# Generate flame graph
cargo flamegraph --bin relay
```

### Network Debugging

**Monitor RPC calls**:
```bash
# Use tcpdump to monitor HTTP traffic
sudo tcpdump -i any -A port 8323

# Monitor specific endpoints
sudo tcpdump -i any -A host localhost and port 8323
```

**Track provider connections**:
```bash
# Monitor connections to blockchain nodes
netstat -an | grep :8545
ss -tuln | grep :8545

# Check connection pool usage
curl http://localhost:8323/metrics | grep connection_pool
```

## Common Debugging Scenarios

### Transaction Failures

**Symptoms**: Transaction shows as failed in status endpoint
**Debugging steps**:
```bash
# 1. Check transaction receipt
cast receipt $TX_HASH --rpc-url http://localhost:8545

# 2. Simulate the call to see revert reason
cast call $ORCHESTRATOR "execute(...)" $PARAMS \
  --from $SENDER \
  --rpc-url http://localhost:8545

# 3. Check contract events
cast logs --address $ORCHESTRATOR \
  --from-block $BLOCK_NUMBER \
  --rpc-url http://localhost:8545

# 4. Verify account delegation
cast call $DELEGATION_PROXY "implementation()" \
  --rpc-url http://localhost:8545
```

### Cross-Chain Issues

**Symptoms**: Multi-chain intent stuck in intermediate state
**Debugging steps**:
```bash
# 1. Check bundle status in database
psql -c "SELECT * FROM bundles WHERE bundle_id = '$BUNDLE_ID';"

# 2. Verify LayerZero messages
cast logs --address $LAYERZERO_ENDPOINT \
  --topics "0x..." \
  --from-block $BLOCK_NUMBER

# 3. Check escrow contract state
cast call $ESCROW_ADDRESS "getLockedFunds(bytes32)" $BUNDLE_ID

# 4. Monitor settlement processing
grep "settlement.*$BUNDLE_ID" relay.log
```

### Price Oracle Issues

**Symptoms**: Quote generation fails or returns stale prices
**Debugging steps**:
```bash
# 1. Check oracle connectivity
curl "https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd"

# 2. Verify cached prices
curl http://localhost:8323/debug/prices | jq

# 3. Check price update logs
grep "price.*update" relay.log

# 4. Test manual price fetch
cast call $ORACLE_ADDRESS "getPrice(address)" $TOKEN_ADDRESS
```

### Database Connection Issues

**Symptoms**: Storage errors or connection timeouts
**Debugging steps**:
```bash
# 1. Test basic connectivity
pg_isready -h $DB_HOST -p $DB_PORT -U $DB_USER

# 2. Check connection limits
psql -c "SHOW max_connections;"
psql -c "SELECT count(*) FROM pg_stat_activity;"

# 3. Monitor connection pool
curl http://localhost:8323/health/storage

# 4. Check for long-running queries
psql -c "SELECT pid, now() - pg_stat_activity.query_start AS duration, query 
         FROM pg_stat_activity 
         WHERE (now() - pg_stat_activity.query_start) > interval '5 minutes';"
```

### Chain State Replication Issues

**Symptoms**: Tests fail with unexpected contract state or "execution reverted" errors that work on mainnet
**Root cause**: Local test environments may not perfectly replicate the exact chain state from production

**Debugging approach**:
```bash
# 1. Log request parameters to understand what the client is trying to do
grep "request.*params" relay.log

# 2. Use cast run-transaction to debug the exact transaction that failed
TX_HASH="0x..." # The failing transaction hash from mainnet
cast run-transaction $TX_HASH --rpc-url $MAINNET_RPC_URL --debug

# 3. Use cast call --trace when available
cast call $CONTRACT "method()" $PARAMS \
  --trace \
  --fork-url $MAINNET_RPC_URL \
  --fork-block-number $SPECIFIC_BLOCK

# 4. When cast fails, fall back to direct debugging
# Use Anvil with mainnet fork at specific block
anvil --fork-url $MAINNET_RPC_URL \
      --fork-block-number $BLOCK_NUMBER \
      --print-traces \
      --port 8545

# 5. Compare contract state between local and mainnet
cast call $CONTRACT "getState()" --rpc-url http://localhost:8545
cast call $CONTRACT "getState()" --rpc-url $MAINNET_RPC_URL
```

**Chain state debugging checklist**:
- Verify fork block number matches the failing transaction context
- Check that all required contracts are deployed at expected addresses
- Confirm token balances and allowances match expected values
- Validate that contract storage slots contain expected data
- Ensure timestamp and block-dependent logic matches mainnet conditions

## Debugging Tools Integration

### Docker Debugging

**Debug container setup**:
```dockerfile
# Dockerfile.debug
FROM rust:1.88-bullseye

# Install debugging tools
RUN apt-get update && apt-get install -y \
    gdb \
    valgrind \
    strace \
    tcpdump \
    postgresql-client \
    curl \
    jq

# Install Foundry
RUN curl -L https://foundry.paradigm.xyz | bash
ENV PATH="/root/.foundry/bin:${PATH}"
RUN foundryup

COPY . /app
WORKDIR /app

# Build with debug symbols
RUN cargo build --profile profiling

CMD ["target/profiling/relay"]
```

**Run debug container**:
```bash
# Build debug image
docker build -f Dockerfile.debug -t relay:debug .

# Run with networking and debugging capabilities
docker run -it --cap-add=SYS_PTRACE --network=host relay:debug bash

# Inside container, run with debugger
gdb target/profiling/relay
```

## Distributed Tracing and Latency Analysis

### Grafana and Tempo Setup

**Access tracing data**:
1. Go to Grafana in the **infra repository**
2. Focus on **ic-1** instance for relay tracing  
3. Select **Tempo** data source
4. Use **Span Tags** filtering with `rpc.method`

### Key Span Tags for Filtering

- `rpc.method = "wallet_prepareCalls"` - Intent preparation requests
- `rpc.method = "wallet_sendPreparedCalls"` - Intent submission requests  
- `rpc.method = "wallet_getCallsStatus"` - Status query requests
- `chain.id` - Filter by specific blockchain (1, 42161, 137, etc.)
- `bundle_id` - Track complete cross-chain execution flows

### Instrumentation

**Add tracing to code**: Use the `#[instrument]` macro from the tracing crate to automatically create spans and record timing data.

**Alloy provider instrumentation**: Blockchain interactions (`eth_call`, `eth_sendRawTransaction`, `eth_getTransactionReceipt`, etc.) are automatically traced.

### Common Analysis Patterns

1. **Request Latency**: Filter by RPC method to see response time breakdowns
2. **Cross-Chain Timing**: Search by `bundle_id` to view complete multi-chain execution timelines
3. **Database Performance**: Filter by `storage.operation` to identify slow queries
4. **Provider Calls**: Analyze blockchain interaction latencies across different chains

## Related Documentation

- **[Testing Guide](testing.md)** - Comprehensive testing patterns and setup
- **[Getting Started](getting-started.md)** - Development environment setup  
- **[Transaction Pipeline](../architecture/transaction-pipeline.md)** - Understanding transaction flow
- **[Cross-Chain Operations](../architecture/cross-chain.md)** - Multi-chain debugging context

---

💡 **Pro Tip**: When debugging multi-chain issues, always start by running Anvil instances with `--print-traces` and use Cast to verify contract state on each chain independently before investigating the relay's cross-chain coordination logic.