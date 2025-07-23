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

**Key configuration files**:
- **`relay.yaml`** - Main configuration (**Implementation**: `src/config.rs:45-120`)
- **`registry.yaml`** - Chain and token registry (**Implementation**: `src/types/coin_registry.rs:25-45`)

Example minimal configuration:

```yaml
# relay.yaml
server:
    address: "127.0.0.1"
    port: 8323

chain:
    endpoints:
        - "http://localhost:8545/"  # Local Anvil instance
    fee_tokens:
        - "0x706aa5c8e5cc2c67da21ee220718f6f6b154e75c"  # Mock ERC20

quote:
    ttl: 300  # 5 minutes
    gas:
        intent_buffer: 25000
        tx_buffer: 1000000
```

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
- **RPC Server** (**Implementation**: `src/spawn.rs:45-78`) - JSON-RPC endpoints
- **Transaction Service** (**Implementation**: `src/transactions/service.rs:85-120`) - Transaction processing
- **Price Oracle** (**Implementation**: `src/price/oracle.rs:65-90`) - Fee conversion
- **Storage Backend** (**Implementation**: `src/storage/pg.rs:45-70`) - PostgreSQL integration

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

**Error hierarchy** (**Implementation**: `src/error/mod.rs:15-45`):
- `RelayError` - Top-level error type
- Module-specific errors in `src/error/` subdirectory
- Error context using `eyre` crate

### Async Patterns

All I/O operations use Tokio async runtime:

**Key patterns**:
- **Service handles** (**Example**: `src/transactions/service.rs:45-65`) - Message-passing between components
- **Background tasks** (**Example**: `src/spawn.rs:120-150`) - Long-running services
- **Database operations** (**Example**: `src/storage/pg.rs:85-120`) - Async SQL with SQLx

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

**Testing setup** (**Implementation**: `tests/e2e/environment.rs:45-120`)

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

For more detailed troubleshooting, see [Common Issues](../troubleshooting/common-issues.md).

---

💡 **Next**: Once you have the relay running, explore the [Architecture Overview](../architecture/overview.md) to understand the system design.