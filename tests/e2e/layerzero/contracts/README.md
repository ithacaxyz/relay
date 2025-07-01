# LayerZero Test Contracts

This directory contains a standalone Foundry project with custom LayerZero test contracts.

## Setup

Use the build script to install dependencies and build contracts:
```bash
cd tests/e2e/layerzero/contracts
./build.sh
```

This script will:
1. Install forge dependencies
2. Copy the EndpointV2Mock from the devtools dependency
3. Build all contracts

## Contracts

- **MockEscrow.sol** - Custom escrow contract that uses LayerZero OApp for cross-chain token transfers
- **MinimalSendReceiveLib.sol** - Minimal implementation of LayerZero send/receive library for testing

## Integration with Tests

The e2e tests expect these contracts to be built and available. The CI workflow builds these contracts separately from the main test contracts.

## Dependencies

Dependencies are managed via `foundry.toml` and installed with `forge install`:
- LayerZero V2 protocol contracts (commit: 4cfd33f)
- LayerZero OApp contracts  
- OpenZeppelin contracts v5.0.2
- Solady v0.0.246