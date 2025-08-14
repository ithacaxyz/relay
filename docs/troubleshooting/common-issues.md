# Common Issues and Solutions

This guide covers the most frequently encountered issues when developing, deploying, or operating the Ithaca Relay, along with their solutions and prevention strategies.

## Development Issues

### Database Connection Problems

#### Issue: "Failed to connect to PostgreSQL"

**Symptoms**:
```
Error: Failed to connect to database
Caused by: Connection refused (os error 111)
```

**Root Causes**:
- PostgreSQL service not running
- Incorrect connection string
- Database doesn't exist
- Permission issues

**Solutions**:

1. **Verify PostgreSQL Service**:
```bash
# Check status
sudo systemctl status postgresql

# Start if needed
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

2. **Check Connection String**:
```bash
# Test connection manually
psql "postgresql://localhost/ithaca_relay" -c "SELECT 1"

# Verify environment variable
echo $DATABASE_URL
```

3. **Create Database and User**:
```bash
# Create database
sudo -u postgres createdb ithaca_relay

# Create user with permissions
sudo -u postgres createuser --superuser $USER
sudo -u postgres psql -c "GRANT ALL ON DATABASE ithaca_relay TO $USER"
```

4. **Fix Connection Parameters**:
```yaml
# relay.yaml
storage:
  url: "postgresql://username:password@localhost:5432/ithaca_relay"
  max_connections: 10
  acquire_timeout: 30
```

**Prevention**:
- Use connection health checks in production
- Monitor database connectivity metrics
- Implement automatic retry logic

---

#### Issue: "Migration failed"

**Symptoms**:
```
Error: Migration 0015_update_intent_structure.sql failed
Caused by: relation "intents" already exists
```

**Root Causes**:
- Partial migration application
- Schema conflicts
- Manual database changes

**Solutions**:

1. **Check Migration Status**:
```bash
# View applied migrations
psql ithaca_relay -c "SELECT * FROM _sqlx_migrations ORDER BY applied_at"
```

2. **Reset Database** (Development Only):
```bash
# Drop and recreate
dropdb ithaca_relay
createdb ithaca_relay

# Restart relay to reapply migrations
cargo run --bin relay
```

3. **Manual Migration Repair**:
```sql
-- Fix partial migration state
DELETE FROM _sqlx_migrations WHERE version = 20231125000015;

-- Manually apply specific changes if needed
ALTER TABLE intents DROP COLUMN IF EXISTS old_column;
```

**Prevention**:
- Always backup before schema changes
- Test migrations on development databases first
- Use atomic migration transactions

---

### Build and Compilation Issues

#### Issue: "Rust version not supported"

**Symptoms**:
```
error: package requires Rust 1.88 or newer
```

**Solutions**:

1. **Update Rust Toolchain**:
```bash
# Update to latest stable
rustup update stable

# Verify version
rustc --version  # Should be 1.88+

# Set default if needed
rustup default stable
```

2. **Install Required Components**:
```bash
# Install nightly for formatting
rustup install nightly
rustup component add rustfmt --toolchain nightly

# Install clippy
rustup component add clippy
```

**Prevention**:
- Pin Rust version in CI/CD
- Document MSRV requirements clearly
- Use rustup for consistent toolchain management

---

#### Issue: "SQLx compile-time verification failed"

**Symptoms**:
```
error: error occurred while running custom build command for `relay`
ERROR: failed to resolve query: relation "transactions" does not exist
```

**Root Causes**:
- Database not running during compilation
- Wrong DATABASE_URL during build
- Missing migrations

**Solutions**:

1. **Set Offline Mode**:
```bash
# Skip database verification during build
export SQLX_OFFLINE=true
cargo build
```

2. **Generate sqlx-data.json**:
```bash
# With database running
cargo sqlx prepare

# Commit the generated file
git add sqlx-data.json
```

3. **Fix Database URL**:
```bash
# Ensure correct URL during build
export DATABASE_URL="postgresql://localhost/ithaca_relay"
```

**Prevention**:
- Always commit sqlx-data.json
- Use offline mode in CI/CD
- Document database setup requirements

---

### Contract Integration Issues

#### Issue: "Contract call failed - not deployed"

**Symptoms**:
```
Error: Contract call failed
Caused by: Contract not deployed at address 0x5FbDB2315678afecb367f032d93F642f64180aa3
```

**Root Causes**:
- Contracts not deployed to current network
- Wrong contract addresses in configuration
- Network mismatch

**Solutions**:

1. **Deploy Test Contracts**:
```bash
cd tests/account

# Build contracts
forge build

# Deploy to local Anvil
forge script script/DeployAll.s.sol --broadcast --rpc-url http://localhost:8545

# Note the deployed addresses
```

2. **Update Configuration**:
```yaml
# relay.yaml
orchestrator: "0x5FbDB2315678afecb367f032d93F642f64180aa3"
delegation_proxy: "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"
simulator: "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"
```

3. **Verify Contract Deployment**:
```bash
# Check contract exists
cast code 0x5FbDB2315678afecb367f032d93F642f64180aa3 --rpc-url http://localhost:8545

# Verify contract function
cast call 0x5FbDB2315678afecb367f032d93F642f64180aa3 "owner()" --rpc-url http://localhost:8545
```

**Prevention**:
- Automate contract deployment in tests
- Use deterministic deployment addresses
- Validate contract addresses on startup

---

## Runtime Issues

### RPC Server Problems

#### Issue: "Port already in use"

**Symptoms**:
```
Error: Address already in use (os error 98)
```

**Solutions**:

1. **Find and Kill Process**:
```bash
# Find process using port 8323
sudo lsof -i :8323

# Kill the process
sudo kill -9 <PID>
```

2. **Use Different Port**:
```bash
# Start on alternative port
cargo run --bin relay -- --port 8324
```

3. **Check for Zombie Processes**:
```bash
# Find relay processes
ps aux | grep relay

# Clean up if needed
pkill -f relay
```

**Prevention**:
- Use proper shutdown handling
- Implement graceful termination
- Monitor port usage in production

---

#### Issue: "CORS errors in browser"

**Symptoms**:
```
Access to fetch at 'http://localhost:8323' from origin 'http://localhost:3000' 
has been blocked by CORS policy
```

**Solutions**:

1. **Configure CORS Origins**:
```yaml
# relay.yaml
server:
  cors_origins:
    - "http://localhost:3000"
    - "https://yourdomain.com"
```

2. **Allow All Origins** (Development Only):
```yaml
# relay.yaml
server:
  cors_origins: ["*"]
```

3. **Verify Headers**:
```bash
# Test CORS headers
curl -H "Origin: http://localhost:3000" \
     -H "Access-Control-Request-Method: POST" \
     -H "Access-Control-Request-Headers: Content-Type" \
     -X OPTIONS \
     http://localhost:8323
```

**Prevention**:
- Always configure CORS for web clients
- Use specific origins in production
- Test CORS in different environments

---

### Transaction Processing Issues

#### Issue: "Quote expired"

**Symptoms**:
```json
{
  "error": {
    "code": -32001,
    "message": "Quote expired",
    "data": {
      "quoteTtl": 1634567890,
      "currentTime": 1634567920
    }
  }
}
```

**Root Causes**:
- Network delays
- Slow user interaction
- Short quote TTL

**Solutions**:

1. **Increase Quote TTL**:
```yaml
# relay.yaml
quote:
  ttl: 600  # 10 minutes instead of 5
```

2. **Optimize Client Flow**:
```typescript
// Prepare and submit immediately
const prepared = await relay.prepareCalls(intent);
const signature = await wallet.signTypedData(prepared.typedData);

// Submit without delay
await relay.sendPreparedCalls({
  context: prepared.context,
  signature,
  key: prepared.key
});
```

3. **Handle Expiration Gracefully**:
```typescript
try {
  await relay.sendPreparedCalls(params);
} catch (error) {
  if (error.code === -32001) {
    // Re-prepare with fresh quote
    const newPrepared = await relay.prepareCalls(originalIntent);
    // ... retry flow
  }
}
```

**Prevention**:
- Set appropriate TTL for user flow
- Implement automatic retry logic
- Monitor quote usage patterns

---

#### Issue: "Insufficient gas for execution"

**Symptoms**:
```
Error: Transaction reverted
Reason: "Out of gas"
Gas used: 500000 / 500000
```

**Root Causes**:
- Incorrect gas estimation
- Gas limit too low
- Complex contract interactions

**Solutions**:

1. **Increase Gas Buffers**:
```yaml
# relay.yaml
quote:
  gas:
    intent_buffer: 50000    # Increased from 25000
    tx_buffer: 2000000      # Increased from 1000000
```

2. **Debug Gas Estimation**:
```bash
# Enable detailed logging
RUST_LOG=debug cargo run --bin relay

# Check simulation logs
```

3. **Manual Gas Override**:
```typescript
// Override gas estimates if needed
const prepared = await relay.prepareCalls({
  calls: [...],
  gasOverrides: {
    gasLimit: 1000000  // Force higher limit
  }
});
```

**Prevention**:
- Monitor gas usage patterns
- Test with various contract complexities
- Implement gas price monitoring

---

### Cross-Chain Issues

#### Issue: "Settlement timeout"

**Symptoms**:
```
Error: Settlement timeout for bundle 0x1234...
Status: SettlementsQueued -> Refunding
```

**Root Causes**:
- LayerZero network congestion
- Incorrect endpoint configuration
- Message verification failures

**Solutions**:

1. **Check LayerZero Status**:
```bash
# Monitor LayerZero network
curl "https://api.layerzero.network/v1/status"

# Check specific message
curl "https://api.layerzero.network/v1/messages/<message-hash>"
```

2. **Increase Settlement Timeout**:
```rust
// In settlement configuration
const SETTLEMENT_TIMEOUT: Duration = Duration::from_secs(3600); // 1 hour
```

3. **Verify Endpoint Configuration**:
```yaml
# relay.yaml
chains:
  - chain_id: 1
    layerzero_endpoint: "0x66A71Dcef29A0fFBDBE3c6a460a3B5BC225Cd675"
  - chain_id: 137  
    layerzero_endpoint: "0x3c2269811836af69497E5F486A85D7316753cf62"
```

**Prevention**:
- Monitor LayerZero network health
- Implement retry mechanisms
- Set appropriate timeouts for network conditions

---

### Network Connectivity Issues

#### Issue: "RPC provider connection failed"

**Symptoms**:
```
Error: Provider error for chain 1
Caused by: Connection timeout after 30s
```

**Root Causes**:
- Provider downtime
- Network connectivity issues
- Rate limiting

**Solutions**:

1. **Test Provider Connectivity**:
```bash
# Test each provider
curl -X POST https://eth-mainnet.alchemyapi.io/v2/YOUR-KEY \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_chainId","id":1}'
```

2. **Configure Multiple Providers**:
```yaml
# relay.yaml
chain:
  endpoints:
    - "http://localhost:8545/"
    - "https://eth-mainnet.alchemyapi.io/v2/YOUR-KEY"
    - "https://mainnet.infura.io/v3/YOUR-KEY"
```

3. **Adjust Timeouts**:
```yaml
# relay.yaml
chain:
  connection_timeout: 60000  # 60 seconds
  request_timeout: 30000     # 30 seconds
```

**Prevention**:
- Use multiple reliable providers
- Monitor provider health
- Implement automatic failover

---

## Performance Issues

### High Memory Usage

#### Issue: "Relay consuming excessive memory"

**Symptoms**:
- Memory usage > 1GB
- Out of memory errors
- System instability

**Debugging**:

1. **Monitor Memory Usage**:
```bash
# Check process memory
ps aux | grep relay

# Detailed memory analysis
valgrind --tool=massif cargo run --bin relay
```

2. **Enable Memory Profiling**:
```bash
# Build with profiling
cargo build --release --features profiling

# Run with memory tracking  
MALLOC_CHECK_=1 cargo run --bin relay
```

**Solutions**:

1. **Optimize Connection Pools**:
```yaml
# relay.yaml
storage:
  max_connections: 5       # Reduce if too high
  idle_timeout: 300        # Close idle connections faster

chain:
  max_connections: 3       # Per provider
```

2. **Configure Cache Limits**:
```rust
// In configuration
const MAX_CACHE_SIZE: usize = 1000;
const CACHE_TTL: Duration = Duration::from_secs(300);
```

3. **Implement Memory Monitoring**:
```rust
// Add memory metrics
let memory_usage = procfs::process::Process::myself()
    .unwrap()
    .stat()
    .unwrap()
    .rss_bytes();

metrics.memory_usage.set(memory_usage as f64);
```

**Prevention**:
- Set resource limits in production
- Monitor memory usage trends
- Implement cache eviction policies

---

### High CPU Usage

#### Issue: "Relay using too much CPU"

**Symptoms**:
- CPU usage > 80%
- Slow response times
- System overload

**Debugging**:

1. **Profile CPU Usage**:
```bash
# Install profiling tools
sudo apt-get install linux-perf

# Profile relay process
sudo perf record -g --call-graph dwarf cargo run --bin relay --release
sudo perf report
```

2. **Enable CPU Profiling**:
```bash
# Build with profiling
cargo build --release --features profiling

# Run with CPU profiler
CPUPROFILE=relay.prof cargo run --bin relay
```

**Solutions**:

1. **Optimize Database Queries**:
```sql
-- Add indexes for frequent queries
CREATE INDEX CONCURRENTLY idx_transactions_bundle_status 
ON transactions(bundle_id, status);

CREATE INDEX CONCURRENTLY idx_bundles_recent 
ON bundles(created_at DESC) WHERE status != 'done';
```

2. **Reduce Polling Frequency**:
```yaml
# relay.yaml
monitoring:
  poll_interval: 10000     # 10 seconds instead of 1
  batch_size: 100          # Process more items per batch
```

3. **Optimize Async Tasks**:
```rust
// Batch operations
let futures = transactions
    .chunks(10)
    .map(|chunk| process_transaction_batch(chunk));

futures::future::join_all(futures).await;
```

**Prevention**:
- Monitor CPU usage patterns
- Profile regularly during development
- Set CPU limits in production

---

## Monitoring and Alerting

### Setting Up Health Checks

#### Application Health

```bash
# Basic health check
curl http://localhost:8323/health

# Component-specific checks
curl http://localhost:8323/health/database
curl http://localhost:8323/health/providers
```

#### Database Health

```sql
-- Monitor active connections
SELECT count(*) as active_connections 
FROM pg_stat_activity 
WHERE state = 'active';

-- Check for long-running queries
SELECT query, query_start, state 
FROM pg_stat_activity 
WHERE state != 'idle' 
AND query_start < NOW() - INTERVAL '5 minutes';
```

#### System Resource Monitoring

```bash
# Monitor system resources
htop
iotop
nethogs

# Check disk usage
df -h
du -sh /var/lib/postgresql/

# Monitor network
netstat -an | grep :8323
ss -tulpn | grep :8323
```

### Key Metrics to Monitor

#### Application Metrics

- **Request Rate**: RPC requests per second
- **Response Time**: P50, P95, P99 latencies
- **Error Rate**: Failed requests percentage
- **Success Rate**: Successful intent executions

#### System Metrics

- **Memory Usage**: RSS, heap usage
- **CPU Usage**: Process and system CPU
- **Disk Usage**: Database and log disk usage
- **Network I/O**: Bandwidth utilization

#### Business Metrics

- **Bundle Success Rate**: Successful vs failed bundles
- **Cross-Chain Volume**: Multi-chain intent volume
- **Average Execution Time**: Intent to confirmation time
- **Liquidity Utilization**: Cross-chain liquidity usage

---

## Debugging Strategies

### Enable Comprehensive Logging

```bash
# Development logging
export RUST_LOG="relay=debug,sqlx=info,reqwest=info"

# Production logging with rotation
export RUST_LOG="relay=info,warn"

# Component-specific debugging
export RUST_LOG="relay::rpc=trace,relay::transactions=debug"
```

### Use Structured Logging

```rust
// Add correlation IDs
tracing::info!(
    bundle_id = %bundle_id,
    chain_id = chain_id,
    "Processing multichain bundle"
);

// Log timing information
let start = Instant::now();
// ... operation
tracing::info!(
    duration_ms = start.elapsed().as_millis(),
    "Operation completed"
);
```

### Database Query Analysis

```sql
-- Enable query logging
ALTER SYSTEM SET log_statement = 'all';
ALTER SYSTEM SET log_min_duration_statement = 1000; -- Log slow queries

-- Analyze query performance
EXPLAIN ANALYZE SELECT * FROM transactions WHERE bundle_id = $1;

-- Check for missing indexes
SELECT schemaname, tablename, attname, n_distinct, correlation 
FROM pg_stats 
WHERE tablename IN ('transactions', 'bundles', 'intents');
```

---

## Getting Help

### Collecting Debug Information

When reporting issues, collect:

1. **System Information**:
```bash
# System details
uname -a
lsb_release -a

# Rust version
rustc --version
cargo --version

# Database version
psql --version
```

2. **Configuration**:
```bash
# Sanitized configuration (remove secrets)
cat relay.yaml | sed 's/password:.*/password: [REDACTED]/'
```

3. **Logs**:
```bash
# Recent application logs
RUST_LOG=debug cargo run --bin relay 2>&1 | tail -1000

# System logs
journalctl -u relay --since "1 hour ago"
```

4. **Resource Usage**:
```bash
# Current resource usage
ps aux | grep relay
free -h
df -h
```

### Issue Reporting Template

```markdown
## Issue Description
Brief description of the problem

## Environment
- OS: [e.g., Ubuntu 22.04]
- Rust version: [e.g., 1.88.0]
- Database: [e.g., PostgreSQL 15.3]
- Commit hash: [git rev-parse HEAD]

## Configuration
[Include relevant relay.yaml sections]

## Steps to Reproduce
1. Step one
2. Step two  
3. Step three

## Expected Behavior
What should happen

## Actual Behavior
What actually happened

## Logs
[Include relevant logs with RUST_LOG=debug]

## Additional Context
Any other relevant information
```

---

## Related Documentation

- **[Getting Started](../development/getting-started.md)** - Initial setup and configuration
- **[Testing Guide](../development/testing.md)** - Testing patterns and debugging
- **[Architecture Overview](../architecture/overview.md)** - System design context
- **[RPC API Reference](https://porto.sh/rpc-server)** - API specifications

---

💡 **Pro Tip**: Most issues can be resolved by enabling debug logging (`RUST_LOG=debug`) and examining the detailed execution flow. The relay provides extensive instrumentation for troubleshooting.
