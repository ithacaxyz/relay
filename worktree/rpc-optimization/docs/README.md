# Ithaca Relay Documentation

Welcome to the Ithaca Relay developer documentation. This documentation is specifically designed for developers working on the relay codebase.

## Quick Links

- **[Relay README](../README.md)** - Basic setup and running instructions

## Documentation Structure

### 🚀 Development
- **[Getting Started](development/getting-started.md)** - Set up your development environment
- **[Testing Guide](development/testing.md)** - Unit tests, e2e tests, and testing patterns
- **[Debugging Guide](development/debugging.md)** - Debugging tools, Anvil traces, Cast CLI, and troubleshooting

### 🏗️ Architecture
- **[System Overview](architecture/overview.md)** - High-level relay architecture and components  
- **[Porto Integration](architecture/porto-integration.md)** - Ecosystem context and intent-based design principles
- **[RPC Endpoints](architecture/rpc-endpoints.md)** - JSON-RPC API implementation details
- **[Transaction Pipeline](architecture/transaction-pipeline.md)** - End-to-end transaction processing flow
- **[Storage Layer](architecture/storage-layer.md)** - Database schema and storage abstractions
- **[Cross-Chain Operations](architecture/cross-chain.md)** - Multichain intent and settlement implementation

### 📡 APIs
- **[RPC API Reference](https://porto.sh/rpc-server)** - Complete JSON-RPC endpoint documentation

### 🔧 Operations
- **[Configuration Reference](development/getting-started.md#configuration)** - Configuration options and examples
- **[Troubleshooting Guide](troubleshooting/common-issues.md)** - Common issues and solutions

### 📊 Diagrams
- **[Bundle State Machine](diagrams/bundle_state_machine.svg)** - Cross-chain bundle processing states

## External Resources

- **[Porto Documentation](https://github.com/ithacaxyz/porto)** - Client SDK and user-facing documentation
- **[Account Contracts](https://github.com/ithacaxyz/account)** - EIP-7702 delegation and orchestrator contracts
- **[Ithaca Protocol](https://porto.sh)** - Protocol overview and specifications
