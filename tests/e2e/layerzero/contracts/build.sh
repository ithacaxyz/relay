#!/bin/bash
set -e

# Install dependencies
forge install foundry-rs/forge-std@v1.9.5 --no-git
forge install vectorized/solady@v0.0.246 --no-git
forge install LayerZero-Labs/LayerZero-v2@88428755be6caa71cb1d2926141d73c8989296b5 --no-git
forge install LayerZero-Labs/devtools@2648a5cb4497019c03d516d809d8be25bfbd1798 --no-git
forge install OpenZeppelin/openzeppelin-contracts@v5.0.2 --no-git

# Copy EndpointV2Mock from devtools after installation
ENDPOINT_MOCK_PATH="lib/devtools/packages/test-devtools-evm-foundry/contracts/mocks/EndpointV2Mock.sol"
if [ -f "$ENDPOINT_MOCK_PATH" ]; then
    cp "$ENDPOINT_MOCK_PATH" src/
    echo "Copied EndpointV2Mock.sol from devtools"
else
    echo "Error: EndpointV2Mock.sol not found at $ENDPOINT_MOCK_PATH"
    echo "Contents of lib/devtools (if exists):"
    ls -la lib/devtools 2>/dev/null || echo "lib/devtools not found"
    exit 1
fi

# Build contracts
forge build