# Ithaca Relay Documentation

Welcome to the Ithaca Relay developer documentation. This documentation is specifically designed for developers working on the relay codebase.

## Quick Links

- **[Relay README](../README.md)** - Basic setup and running instructions

## Documentation Structure

### 🚀 Development
- **[Getting Started](development/getting-started.md)** - Set up your development environment
- **[Testing Guide](development/testing.md)** - Unit tests, e2e tests, and testing patterns
- **[Contributing](development/contributing.md)** - Code style, PR guidelines, and conventions

### 🏗️ Architecture
- **[Porto Integration](architecture/porto-integration.md)** - Ecosystem context and intent-based design principles
- **[System Overview](architecture/overview.md)** - High-level relay architecture and components  
- **[RPC Endpoints](architecture/rpc-endpoints.md)** - JSON-RPC API implementation details
- **[Transaction Pipeline](architecture/transaction-pipeline.md)** - End-to-end transaction processing flow
- **[Storage Layer](architecture/storage-layer.md)** - Database schema and storage abstractions
- **[Cross-Chain Operations](architecture/cross-chain.md)** - Multichain intent and settlement implementation

### 📡 APIs
- **[RPC API Reference](apis/rpc-reference.md)** - Complete JSON-RPC endpoint documentation
- **[Internal APIs](apis/internal-apis.md)** - Service interfaces and internal communication

### 🔧 Troubleshooting
- **[Common Issues](troubleshooting/common-issues.md)** - Frequent problems and solutions
- **[Debugging Guide](troubleshooting/debugging.md)** - Tools and techniques for debugging

### 📊 Diagrams
- **[Bundle State Machine](diagrams/bundle_state_machine.svg)** - Cross-chain bundle processing states

## Code Reference Convention

This documentation uses **file:line** references to actual code instead of copying code snippets. This ensures documentation stays up-to-date as the codebase evolves.

**Example format**:
```markdown
**Implementation**: `src/rpc/relay.rs`
**Related types**: `src/types/rpc/calls.rs`
```

When code moves or changes, simply update the line numbers rather than maintaining duplicate code blocks.

## Development Workflow

1. **Setup**: Follow [Getting Started](development/getting-started.md)
2. **Code**: Use patterns from [CLAUDE.md](../CLAUDE.md)
3. **Test**: See [Testing Guide](development/testing.md) 
4. **Contribute**: Follow [Contributing](development/contributing.md)

## External Resources

- **[Porto Documentation](https://github.com/ithacaxyz/porto)** - Client SDK and user-facing documentation
- **[Account Contracts](https://github.com/ithacaxyz/account)** - EIP-7702 delegation and orchestrator contracts
- **[Ithaca Protocol](https://porto.sh)** - Protocol overview and specifications
