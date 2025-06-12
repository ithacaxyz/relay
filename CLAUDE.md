# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Development Commands

### Building
- `make build` - Build release binary with profiling profile
- `make build-debug` - Build debug binary
- `cargo build` - Standard cargo build
- `make maxperf` - Build with maximum optimization
- `make install` - Install to ~/.cargo/bin

### Testing
- `cargo test` or `make test` - Run all tests
- `make test-unit` - Run unit tests with cargo-nextest
- `make cov-unit` - Run unit tests with coverage
- `make cov-report-html` - Generate HTML coverage report
- Run e2e tests:
  ```bash
  cd tests/account
  forge build && forge build lib/solady/test/utils/mocks/MockERC20.sol && forge build lib/solady/test/utils/mocks/MockERC721.sol
  TEST_CONTRACTS=$(pwd)/out cargo test -- e2e
  ```

### Code Quality
- `make fmt` - Format code (uses nightly)
- `make lint` - Run clippy linting
- `make fix-lint` - Fix linting issues
- `make pr` - Run both lint and tests (for PR checks)
- `make check-features` - Check feature combinations

### Running the Relay
```bash
cargo run --bin relay -- \
    --endpoint $RPC_URL \
    --fee-token $FEE_TOKEN_ADDR \
    --signers-mnemonic $SIGNING_KEY_MNEMONIC \
    --orchestrator $ORCHESTRATOR_ADDR \
    --delegation-proxy $DELEGATION_PROXY_ADDR \
    --simulator $SIMULATOR_ADDR
```

## Architecture Overview

The Ithaca Relay is a transparent cross-chain transaction router for EIP-7702 accounts. It sponsors transactions and provides fee abstraction services.

### Core Components

1. **RPC Server** (`src/rpc/`): JSON-RPC endpoints
   - `account.rs`: Account management endpoints
   - `onramp.rs`: Onramp functionality
   - `relay.rs`: Main relay endpoints

2. **Transaction Processing** (`src/transactions/`):
   - `service.rs`: Core transaction service logic
   - `fees.rs`: Fee calculation and management
   - `monitor.rs`: Transaction monitoring
   - `signer.rs`: Transaction signing coordination

3. **Storage Layer** (`src/storage/`):
   - `pg.rs`: PostgreSQL implementation
   - `memory.rs`: In-memory storage for testing
   - `api.rs`: Storage trait definitions
   - Database migrations in `migrations/`

4. **Signers** (`src/signers/`):
   - `p256.rs`: P256 elliptic curve signing
   - `webauthn.rs`: WebAuthn authentication
   - `dyn.rs`: Dynamic signer selection

5. **Price Oracle** (`src/price/`):
   - `oracle.rs`: Price oracle coordination
   - `fetchers/coingecko.rs`: CoinGecko price fetcher

6. **Types** (`src/types/`):
   - Core domain types and structures
   - Contract interfaces
   - RPC request/response types

### Key Patterns

- **Error Handling**: Comprehensive error types in `src/error/`
- **Metrics**: Prometheus metrics throughout, periodic jobs in `src/metrics/periodic/`
- **Configuration**: YAML config with CLI overrides via `src/config.rs`
- **Async Runtime**: Tokio-based async throughout
- **Chain Interaction**: Uses Alloy for Ethereum interaction

### Development Notes

- MSRV: 1.85
- Rust Edition: 2024
- Uses SQLx for compile-time checked SQL queries
- Strict clippy linting with warnings as errors
- OpenTelemetry tracing for observability
- WebSocket and HTTP provider support for chain connections

### Testing Guidelines

When creating tests that require a provider or chain interaction:
- **Always use the test environment from `tests/e2e/environment.rs`**
- Do not create standalone provider instances or custom test setups
- The e2e environment provides:
  - Pre-configured Anvil instance (or external node support)
  - Deployed test contracts (orchestrator, delegation, simulator, ERC20s, ERC721)
  - Funded test accounts and signers
  - Relay service integration
  - Proper chain configuration

Example:
```rust
use crate::e2e::Environment;

#[tokio::test]
async fn test_with_provider() {
    let env = Environment::setup().await.unwrap();
    // Use env.provider for chain interactions
    // Use env.relay_endpoint for relay RPC calls
    // Access deployed contracts via env.orchestrator, env.delegation, etc.
}
```

## GitHub Integration

When you need to fetch information from GitHub (issues, pull requests, releases, etc.), always prefer using the GitHub CLI (`gh`) over web fetching. The `gh` command provides direct access to GitHub's API and is more reliable than web scraping.

Examples:
- `gh pr list` - List pull requests
- `gh issue view <number>` - View a specific issue
- `gh api repos/ithacaxyz/relay/pulls/<number>/comments` - Get PR comments
- `gh release list` - List releases

## Commit Convention

This project follows [Conventional Commits](https://www.conventionalcommits.org/) for commit messages. Use the following format:

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, missing semicolons, etc.)
- `refactor`: Code refactoring without changing functionality
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `build`: Changes to build system or dependencies
- `ci`: CI/CD configuration changes
- `chore`: Other changes that don't modify src or test files
- `revert`: Reverting a previous commit

### Examples
- `feat(rpc): add new relay endpoint for batch transactions`
- `fix(storage): handle null values in transaction queries`
- `docs: update README with new configuration options`
- `chore(deps): bump alloy from 0.1.0 to 0.2.0`
- `refactor(transactions): simplify fee calculation logic`

## Code Style Preferences

### Serialization and Deserialization

1. **Always use derive macros** for JSON serialization:
   - Prefer `#[derive(Serialize, Deserialize)]` over manual JSON construction
   - Use serde's attribute macros for field customization when needed
   - Never manually build JSON objects when structs with derives can handle it

2. **Use Alloy's built-in helpers**:
   - Don't manually implement serialization/deserialization for Ethereum types
   - The `alloy` crate provides helpers for common Ethereum data types
   - Use Alloy's serialization traits and derives whenever working with chain data

3. **Struct-based APIs**:
   - Define proper request/response structs for all RPC methods
   - Use type-safe representations instead of raw JSON values
   - Leverage serde's powerful derive system for automatic conversion

Example of preferred style:
```rust
// GOOD: Using derives and structs
#[derive(Serialize, Deserialize)]
struct TransactionRequest {
    from: Address,
    to: Address,
    value: U256,
}

// BAD: Manual JSON construction
let json = json!({
    "from": from.to_string(),
    "to": to.to_string(),
    "value": value.to_string(),
});
```