#\!/bin/bash

# Run RPC cache tests with local Anvil instance

echo "Running RPC cache tests with local Anvil on port 8545..."
echo "================================"

# First, build the test contracts if needed
echo "Building test contracts..."
cd tests/account
forge build
forge build lib/solady/test/utils/mocks/MockERC20.sol
forge build lib/solady/test/utils/mocks/MockERC721.sol
cd ../..

# Set environment variables to use your local Anvil
export TEST_EXTERNAL_ANVIL="http://localhost:8545"
export TEST_CONTRACTS="$(pwd)/tests/account/out"
export RUST_LOG=relay=debug,test=debug

# Run only the RPC cache tests
echo ""
echo "Running RPC cache tests..."
echo "================================"
cargo test --test e2e rpc_cache -- --nocapture

# Optional: Run with more verbose output
# cargo test --test e2e rpc_cache -- --nocapture --test-threads=1

echo ""
echo "Tests complete\!"
