# Getting Started with Relay Development

This guide will help you set up your development environment for working on the Ithaca Relay.

## Prerequisites

### Required Tools

- **Rust** (1.88+ with 2024 edition support)
- **PostgreSQL** (for storage backend)
- **Foundry** (`forge`, `cast`, `anvil`) - for contract interaction and testing
- **cargo-nextest** - for enhanced testing: `cargo install cargo-nextest`

### Optional Tools

- **Docker** - for containerized development
- **GitHub CLI** (`gh`) - for GitHub integration (preferred over web API)

## Initial Setup

### 1. Clone and Build

```bash
# Clone the repository (if not already done)
git clone https://github.com/ithacaxyz/relay.git
cd relay

# Initialize git submodules for e2e tests
git submodule update --init --recursive

# Build the relay
make build
# or for debug build
make build-debug
```

### 2. Database Setup

The relay requires PostgreSQL for persistent storage:

```bash
# Install PostgreSQL (Ubuntu/Debian)
sudo apt-get install postgresql postgresql-contrib

# Create database and user
sudo -u postgres createdb ithaca_relay
sudo -u postgres createuser --superuser $USER

# Set database URL
export DATABASE_URL="postgresql://localhost/ithaca_relay"
```

**Database migrations** are applied automatically on startup. See migration files in `migrations/` directory.

### 3. Configuration

Create a basic configuration file:

```bash
# This creates relay.yaml in the working directory
cargo run --bin relay -- --help
```

## Configuration

The relay uses YAML configuration files with CLI override support.

**Key configuration files**:
- **`relay.yaml`** - Main configuration (**Implementation**: `src/config.rs`)

### Configuration Structure

**Complete configuration example**:

```yaml
# relay.yaml - Production configuration
server:
  address: "0.0.0.0"                  # Bind address (0.0.0.0 for Docker)
  port: 8323                          # RPC port
  metrics_port: 9000                  # Prometheus metrics port
  max_connections: 1000               # Maximum concurrent connections

chain:
  endpoints:
    - "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY"
    - "https://polygon-mainnet.g.alchemy.com/v2/YOUR_KEY"
  sequencer_endpoints:                # Optional faster endpoints
    42161: "https://arb1.arbitrum.io/rpc"
  fee_tokens:                         # Accepted fee tokens
    - "0x0000000000000000000000000000000000000000"  # Native ETH
    - "0xA0b86a33E6411B10FdF6FFf01d7F37e6E8C29D21"  # USDC
    - "0xdAC17F958D2ee523a2206206994597C13D831ec7"  # USDT
  interop_tokens:                     # Cross-chain tokens
    - address: "0xA0b86a33E6411B10FdF6FFf01d7F37e6E8C29D21"  # USDC
      chains: [1, 137, 42161]         # Ethereum, Polygon, Arbitrum
  fee_recipient: "0x742d35Cc..."      # Address to receive fees

quote:
  ttl: 300                            # Quote expiration (seconds)
  rate_ttl: 300                       # Price rate cache duration
  constant_rate: null                 # Fixed rate for testing (optional)
  gas:
    intent_buffer: 25000              # Extra gas for intent execution
    tx_buffer: 1000000                # Extra gas for transaction overhead

transactions:
  num_signers: 8                      # Number of transaction signers
  max_pending_transactions: 100       # Max pending per signer
  max_transactions_per_signer: 16     # Max transactions per signer
  max_queued_per_eoa: 1              # Max queued per account
  balance_check_interval: 30          # Balance check frequency (seconds)
  nonce_check_interval: 60            # Nonce synchronization (seconds)
  transaction_timeout: 300            # Transaction timeout (seconds)
  priority_fee_percentile: 20         # Gas price percentile

# Cross-chain configuration (optional)
interop:
  enabled: true
  timeout: 300                        # Cross-chain timeout (seconds)
  max_source_chains: 3               # Maximum funding sources
  layerzero:
    endpoint: "0x66A71Dcef29A0fFBDBE3c6a460a3B5BC225Cd675"
    chain_mapping:
      1: 101       # Ethereum -> LayerZero ID
      137: 109     # Polygon -> LayerZero ID
      42161: 110   # Arbitrum -> LayerZero ID

# Email service (optional)
email:
  porto_base_url: "https://id.porto.sh"
  resend_api_key: "re_YOUR_API_KEY"   # Resend API key

# Onramp integration (optional)
onramp:
  banxa:
    api_url: "https://api.banxa.com/"
    blockchain: "ethereum"
    secrets:
      api_key: "your_banxa_api_key"
      signing_key: "your_banxa_signing_key"

# Contract addresses (required)
orchestrator: "0x1234..."            # Main orchestrator contract
delegation_proxy: "0x5678..."         # Delegation proxy contract
simulator: "0x9abc..."               # Simulation contract
funder: "0xdef0..."                  # Funder contract
escrow: "0x2468..."                  # Escrow factory

# Legacy contract support
legacy_orchestrators: []             # Previous orchestrator versions
legacy_delegation_proxies: []       # Previous delegation proxies

# Database (optional, defaults to memory)
database_url: "postgresql://user:pass@localhost:5432/relay"

# Secrets (environment variables or CLI)
secrets:
  quote_signer: "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
  funder_signer: "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"
  relay_signers:
    - "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    - "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
```

### Environment-Specific Configurations

#### Development Configuration

```yaml
# relay-dev.yaml
server:
  address: "127.0.0.1"
  port: 8323

chain:
  endpoints:
    - "http://localhost:8545"         # Local Anvil
  fee_tokens:
    - "0x0000000000000000000000000000000000000000"  # Native ETH

quote:
  ttl: 30                             # Shorter TTL for testing
  constant_rate: 1.0                  # Fixed exchange rate

transactions:
  num_signers: 2                      # Fewer signers for dev
  balance_check_interval: 5           # More frequent checks

# Use memory storage for development
database_url: null

# Test contracts (deployed via scripts)
orchestrator: "0x5FbDB2315678afecb367f032d93F642f64180aa3"
delegation_proxy: "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"
simulator: "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"
```

#### Docker Configuration

```yaml
# relay-docker.yaml
server:
  address: "0.0.0.0"                  # Accept external connections
  port: 8323

chain:
  endpoints:
    - "${RPC_URL_MAINNET}"            # Environment variable
    - "${RPC_URL_POLYGON}"

# Production database
database_url: "postgresql://relay:${DB_PASSWORD}@postgres:5432/relay"

# Use environment variables for secrets
secrets:
  quote_signer: "${QUOTE_SIGNER_KEY}"
  funder_signer: "${FUNDER_SIGNER_KEY}"
```

### Configuration Validation

The relay validates configuration on startup:

```bash
# Validate configuration without starting
cargo run --bin relay -- --config relay.yaml --config-only

# Check configuration with verbose output
RUST_LOG=debug cargo run --bin relay -- --config relay.yaml --config-only
```

### CLI Overrides

CLI arguments override configuration file values:

```bash
# Override port and address
cargo run --bin relay -- \
  --config relay.yaml \
  --http.port 9119 \
  --http.addr 0.0.0.0

# Override contract addresses
cargo run --bin relay -- \
  --config relay.yaml \
  --orchestrator 0x1234... \
  --delegation-proxy 0x5678...
```

### Environment Variables

Configuration supports environment variable substitution:

```yaml
# Use environment variables in config
server:
  port: ${RELAY_PORT:-8323}           # Default to 8323

chain:
  endpoints:
    - "${RPC_URL_MAINNET:?required}"  # Required variable

database_url: "${DATABASE_URL}"

secrets:
  quote_signer: "${QUOTE_SIGNER_KEY}"
```

### Configuration Precedence

1. **CLI arguments** (highest priority)
2. **Environment variables** 
3. **Configuration file**
4. **Default values** (lowest priority)

## Development Workflow

### Building and Testing

```bash
# Format code (uses nightly rustfmt)
make fmt

# Run linting
make lint

# Run unit tests
make test-unit

# Run all tests
make test

# Full PR check (lint + test)
make pr
```

### Running the Relay

For development, you'll typically run against a local Anvil instance:

```bash
# Terminal 1: Start Anvil
anvil --host 0.0.0.0

# Terminal 2: Deploy contracts (if needed)
# See tests/account/README.md for contract deployment

# Terminal 3: Run relay
cargo run --bin relay -- \
    --endpoint http://localhost:8545 \
    --fee-token 0x706aa5c8e5cc2c67da21ee220718f6f6b154e75c \
    --signers-mnemonic "test test test test test test test test test test test junk"
```

**Key components started**:
- **RPC Server** (**Implementation**: `src/spawn.rs`) - JSON-RPC endpoints
- **Transaction Service** (**Implementation**: `src/transactions/service.rs`) - Transaction processing
- **Price Oracle** (**Implementation**: `src/price/oracle.rs`) - Fee conversion
- **Storage Backend** (**Implementation**: `src/storage/pg.rs`) - PostgreSQL integration

### Development Tools

**Build commands** (see **[CLAUDE.md](../CLAUDE.md)** for complete list):
- `make build` - Release build with profiling
- `make maxperf` - Maximum optimization build
- `make install` - Install to ~/.cargo/bin

**Code quality**:
- `make fmt` - Format code
- `make lint` - Run clippy linting  
- `make fix-lint` - Auto-fix lint issues
- `make check-features` - Verify feature combinations

## IDE Setup

### VS Code

Recommended extensions:
- **rust-analyzer** - Rust language server
- **Error Lens** - Inline error display
- **PostgreSQL** - Database management

### Configuration

The relay uses several Rust-specific configurations:
- **Edition**: 2024 (**Config**: `Cargo.toml:3`)
- **MSRV**: 1.88 (**Config**: `Cargo.toml:4`) 
- **Clippy**: Strict linting with warnings as errors (**Config**: `clippy.toml`)
- **Rustfmt**: Custom formatting rules (**Config**: `rustfmt.toml`)

## Common Development Patterns

### Error Handling

The relay uses comprehensive error types:

**Error hierarchy** (**Implementation**: `src/error/mod.rs`):
- `RelayError` - Top-level error type
- Module-specific errors in `src/error/` subdirectory
- Error context using `eyre` crate

### Async Patterns

All I/O operations use Tokio async runtime:

**Key patterns**:
- **Service handles** (**Example**: `src/transactions/service.rs`) - Message-passing between components
- **Background tasks** (**Example**: `src/spawn.rs`) - Long-running services
- **Database operations** (**Example**: `src/storage/pg.rs`) - Async SQL with SQLx

### Testing Patterns

**Always use the e2e environment** for tests requiring chain interaction:

```rust
use crate::e2e::Environment;

#[tokio::test]
async fn test_relay_feature() {
    let env = Environment::setup().await.unwrap();
    // Use env.provider, env.relay_endpoint, etc.
}
```

**Testing setup** (**Implementation**: `tests/e2e/environment.rs`)

## Next Steps

1. **Read the architecture overview**: [System Overview](../architecture/overview.md)
2. **Explore the codebase**: Start with `src/lib.rs` and follow the module structure
3. **Run tests**: `make test` to ensure everything works
4. **Try e2e tests**: Follow [Testing Guide](testing.md)
5. **Make changes**: Follow [Contributing Guide](contributing.md)

## Troubleshooting

### Common Issues

**Database connection errors**:
- Ensure PostgreSQL is running and accessible
- Check `DATABASE_URL` environment variable
- Verify user permissions

**Build failures**:
- Update Rust toolchain: `rustup update`
- Clean build: `cargo clean && make build`
- Check MSRV compatibility

**Test failures**:
- Ensure contracts are built: see [Testing Guide](testing.md)
- Check Anvil is accessible if using external node
- Verify test environment variables

For detailed logs and debugging, check the relay output and use `cargo run --bin relay -- --help` for additional options.

---

💡 **Next**: Once you have the relay running, explore the [Architecture Overview](../architecture/overview.md) to understand the system design.
