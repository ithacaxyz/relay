#\!/bin/bash

echo "Running RPC Cache Integration Tests with Anvil"
echo "=============================================="
echo ""

export TEST_EXTERNAL_ANVIL="ws://localhost:8545"
export TEST_CONTRACTS="$(pwd)/tests/account/out"
export RUST_LOG="relay::cache=debug,relay::provider=debug"

echo "Test 10: Integration with Environment"
echo "--------------------------------------"
cargo test test_integration_with_environment -- --nocapture --test-threads=1 2>&1 | grep -E "test_integration|cache|HIT|MISS|Caching|PASSED|FAILED|ok$"

echo ""
echo "Test 11: Cached Provider Wrapper"
echo "---------------------------------"
cargo test test_cached_provider_wrapper -- --nocapture --test-threads=1 2>&1 | grep -E "test_cached_provider|cache|HIT|MISS|Caching|PASSED|FAILED|ok$"

echo ""
echo "Test 16: Cache Performance Improvement"
echo "---------------------------------------"
cargo test test_cache_performance_improvement -- --nocapture --test-threads=1 2>&1 | grep -E "test_cache_performance|cache|HIT|MISS|Caching|duration|faster|PASSED|FAILED|ok$"
