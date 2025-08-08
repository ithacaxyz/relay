#\!/bin/bash

echo "==================================================="
echo "RPC Cache Behavior Test - Showing Cache HIT/MISS"
echo "==================================================="
echo ""

export TEST_EXTERNAL_ANVIL="ws://localhost:8545"
export TEST_CONTRACTS="$(pwd)/tests/account/out"

# Run with detailed cache logging
echo "Running test with cache debug logging enabled..."
echo "Watch for:"
echo "  - 'cache MISS' = First call, fetching from Anvil"
echo "  - 'cache HIT' = Using cached value, no RPC call"
echo "  - 'Caching' = Storing value in cache"
echo ""

RUST_LOG="relay::cache=debug,relay::provider=debug" cargo test test_cached_provider_wrapper -- --nocapture --test-threads=1 2>&1 | grep -E "Chain ID|Code cache|Fee history|Caching|HIT|MISS" | sed 's/.*\[0m//'

echo ""
echo "Summary:"
echo "--------"
echo "1. Chain ID: Cached permanently (never expires)"
echo "2. Contract Code: Cached with 30-min TTL"
echo "3. Fee History: Cached without TTL"
echo "4. Second calls show 'HIT' - no RPC to Anvil needed\!"
