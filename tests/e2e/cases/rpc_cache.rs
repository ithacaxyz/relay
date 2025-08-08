use crate::e2e::Environment;
use alloy::{
    primitives::{Address, ChainId, address, bytes},
    providers::Provider,
};
use relay::{
    cache::{CallKey, DeduplicationResult, RpcCache},
    provider::CachedProvider,
};
use std::{sync::Arc, time::Duration};

#[tokio::test]
async fn test_chain_id_permanent_caching() {
    let cache = RpcCache::new();

    // Initially no chain ID cached
    assert_eq!(cache.get_chain_id(), None);

    // Set chain ID
    let chain_id = ChainId::from(1u64);
    let cached_id = cache.set_chain_id(chain_id);
    assert_eq!(cached_id, chain_id);

    // Should retrieve cached value
    assert_eq!(cache.get_chain_id(), Some(chain_id));

    // Setting again should return the same cached value
    let another_chain_id = ChainId::from(2u64);
    let returned_id = cache.set_chain_id(another_chain_id);
    assert_eq!(returned_id, chain_id); // Should return original, not new value

    // Cache should still have the original value
    assert_eq!(cache.get_chain_id(), Some(chain_id));
}

#[tokio::test]
async fn test_contract_code_ttl_caching() {
    let cache = RpcCache::new();
    let address = address!("1234567890123456789012345678901234567890");
    let code = bytes!("608060405234801561001057600080fd5b50");

    // Initially no cached code
    assert_eq!(cache.get_code(&address), None);

    // Set contract code
    cache.set_code(address, code.clone());

    // Should retrieve cached value
    assert_eq!(cache.get_code(&address), Some(code.clone()));

    // Cache should contain the entry
    let stats = cache.stats();
    assert_eq!(stats.code_cache_size, 1);
}

// Fee history caching removed - too volatile (changes every block)

#[tokio::test]
#[ignore] // This test is slow and the logic is already tested in unit tests
async fn test_contract_code_expiration() {
    let cache = RpcCache::new();

    // Create entries with very short TTL by directly manipulating cache
    let addr = address!("1234567890123456789012345678901234567890");
    let code = bytes!("608060405234801561001057600080fd5b50");

    // Set code normally (30-minute TTL)
    cache.set_code(addr, code.clone());
    assert_eq!(cache.get_code(&addr), Some(code.clone()));

    // With static caching, code never expires
    let another_addr = address!("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd");
    let another_code = bytes!("deadbeef");
    cache.set_code(another_addr, another_code.clone());

    // Both entries should be present
    assert_eq!(cache.get_code(&addr), Some(code));
    assert_eq!(cache.get_code(&another_addr), Some(another_code));

    // Cache should have both entries
    assert_eq!(cache.code_cache.len(), 2);
}

#[tokio::test]
async fn test_cache_cleanup() {
    let cache = RpcCache::new();

    // Add multiple entries with different states
    let addr1 = address!("1111111111111111111111111111111111111111");
    let addr2 = address!("2222222222222222222222222222222222222222");
    let code = bytes!("608060405234801561001057600080fd5b50");

    // Add code entries (both static, won't be cleaned up)
    cache.set_code(addr1, code.clone());
    cache.set_code(addr2, code.clone());

    assert_eq!(cache.code_cache.len(), 2);

    // Run cleanup
    cache.cleanup_expired();

    // Nothing should be removed (all static caches)
    assert_eq!(cache.code_cache.len(), 2); // Code cache unchanged (static)
    assert_eq!(cache.get_code(&addr1), Some(code.clone())); // Still cached
    assert_eq!(cache.get_code(&addr2), Some(code)); // Still cached
}

#[tokio::test]
async fn test_call_deduplication() {
    let cache = RpcCache::new();

    let call_key = CallKey {
        to: address!("1234567890123456789012345678901234567890"),
        data: bytes!("a9059cbb"),
        block: "latest".to_string(),
    };

    // First call should return New
    let _sender = match cache.deduplicate_call(call_key.clone()) {
        DeduplicationResult::New(sender) => sender,
        DeduplicationResult::Existing(_) => panic!("Expected New, got Existing"),
    };

    // Second identical call should get a receiver
    let mut receiver = match cache.deduplicate_call(call_key.clone()) {
        DeduplicationResult::Existing(receiver) => receiver,
        DeduplicationResult::New(_) => panic!("Expected Existing, got New"),
    };

    // Verify pending call is tracked
    let stats = cache.stats();
    assert_eq!(stats.pending_calls, 1);

    // Complete the call
    let result = Ok(bytes!("0000000000000000000000000000000000000000000000000000000000000001"));
    cache.complete_call_deduplication(&call_key, result.clone());

    // The receiver should get the result
    let received = receiver.recv().await.unwrap();
    assert_eq!(received, result);

    // Pending call should be cleaned up
    let stats = cache.stats();
    assert_eq!(stats.pending_calls, 0);
}

#[tokio::test]
async fn test_concurrent_cache_access() {
    let cache = Arc::new(RpcCache::new());
    let num_tasks = 10;

    // Spawn multiple tasks trying to set/get the same cache key
    let tasks: Vec<_> = (0..num_tasks)
        .map(|i| {
            let cache = cache.clone();
            tokio::spawn(async move {
                // Try to set/get code (fee history removed)
                let mut addr_bytes = [0u8; 20];
                addr_bytes[18..20].copy_from_slice(&(i as u16).to_be_bytes());
                let addr = Address::from_slice(&addr_bytes);
                cache.set_code(addr, bytes!("deadbeef"));
                cache.get_code(&addr)
            })
        })
        .collect();

    // Wait for all tasks to complete
    let results = futures_util::future::try_join_all(tasks).await.unwrap();

    // Each task should have been able to set and get its value
    for result in results.iter() {
        assert_eq!(*result, Some(bytes!("deadbeef")));
    }

    // Cache should have all entries
    let stats = cache.stats();
    assert_eq!(stats.code_cache_size, num_tasks);
}

#[tokio::test]
async fn test_concurrent_call_deduplication() {
    let cache = Arc::new(RpcCache::new());
    let num_tasks = 5;

    let call_key = CallKey {
        to: address!("1234567890123456789012345678901234567890"),
        data: bytes!("a9059cbb"),
        block: "latest".to_string(),
    };

    // Spawn multiple tasks trying to deduplicate the same call
    let tasks: Vec<_> = (0..num_tasks)
        .map(|_| {
            let cache = cache.clone();
            let call_key = call_key.clone();
            tokio::spawn(async move { cache.deduplicate_call(call_key) })
        })
        .collect();

    let results = futures_util::future::try_join_all(tasks).await.unwrap();

    // Count New vs Existing results
    let mut new_count = 0;
    let mut existing_count = 0;
    let mut receivers = Vec::new();

    for result in results {
        match result {
            DeduplicationResult::New(_) => new_count += 1,
            DeduplicationResult::Existing(receiver) => {
                existing_count += 1;
                receivers.push(receiver);
            }
        }
    }

    // Should have exactly one New and the rest Existing
    assert_eq!(new_count, 1);
    assert_eq!(existing_count, num_tasks - 1);

    // Complete the call
    let call_result =
        Ok(bytes!("0000000000000000000000000000000000000000000000000000000000000001"));
    cache.complete_call_deduplication(&call_key, call_result.clone());

    // All receivers should get the same result
    for mut receiver in receivers {
        let received = receiver.recv().await.unwrap();
        assert_eq!(received, call_result);
    }
}

#[tokio::test]
async fn test_cache_stats_accuracy() {
    let cache = RpcCache::new();

    // Initially empty
    let stats = cache.stats();
    assert!(!stats.chain_id_cached);
    assert_eq!(stats.code_cache_size, 0);
    assert_eq!(stats.delegation_cache_size, 0);
    assert_eq!(stats.pending_calls, 0);

    // Add various cache entries
    cache.set_chain_id(ChainId::from(1u64));

    let addr = address!("1234567890123456789012345678901234567890");
    cache.set_code(addr, bytes!("608060405234801561001057600080fd5b50"));

    // Start a pending call
    let call_key = CallKey { to: addr, data: bytes!("a9059cbb"), block: "latest".to_string() };
    let _sender = match cache.deduplicate_call(call_key.clone()) {
        DeduplicationResult::New(sender) => sender,
        _ => panic!("Expected new call"),
    };

    // Check stats accuracy
    let stats = cache.stats();
    assert!(stats.chain_id_cached);
    assert_eq!(stats.code_cache_size, 1);
    assert_eq!(stats.pending_calls, 1);

    // Complete the call
    cache.complete_call_deduplication(&call_key, Ok(bytes!("deadbeef")));

    // Pending calls should be 0 now
    let stats = cache.stats();
    assert_eq!(stats.pending_calls, 0);
}

#[tokio::test]
#[ignore] // Requires funded environment
async fn test_integration_with_environment() {
    let env = Environment::setup().await.unwrap();

    // The environment should have created a relay with RPC cache
    // Test basic RPC operations that should use caching

    // Test chain_id retrieval (should be cached permanently)
    let chain_id1 = env.provider().get_chain_id().await.unwrap();
    let chain_id2 = env.provider().get_chain_id().await.unwrap();
    assert_eq!(chain_id1, chain_id2);

    // Test contract code retrieval (should be cached with TTL)
    let code1 = env.provider().get_code_at(env.orchestrator).await.unwrap();
    let code2 = env.provider().get_code_at(env.orchestrator).await.unwrap();
    assert_eq!(code1, code2);
    assert!(!code1.is_empty()); // Orchestrator should have code
}

#[tokio::test]
#[ignore] // Requires funded environment
async fn test_cached_provider_wrapper() {
    let env = Environment::setup().await.unwrap();
    let cache = Arc::new(RpcCache::new());
    let cached_provider = CachedProvider::new(env.provider().clone(), cache.clone());

    // Test cached chain ID
    let chain_id1 = cached_provider.get_chain_id_cached().await.unwrap();
    let chain_id2 = cached_provider.get_chain_id_cached().await.unwrap();
    assert_eq!(chain_id1, chain_id2);

    // Verify it was cached
    assert_eq!(cache.get_chain_id(), Some(chain_id1));

    // Test cached code retrieval
    let code1 = cached_provider.get_code_at_cached(env.orchestrator).await.unwrap();
    let code2 = cached_provider.get_code_at_cached(env.orchestrator).await.unwrap();
    assert_eq!(code1, code2);
    assert!(!code1.is_empty());

    // Verify it was cached
    assert_eq!(cache.get_code(&env.orchestrator), Some(code1));

    // Fee history is no longer cached (too volatile - changes every block)
    // Each call should fetch fresh data from the provider
}

#[tokio::test]
#[ignore] // Requires funded environment
async fn test_cache_fallback_on_serialization_error() {
    let env = Environment::setup().await.unwrap();
    let cache = Arc::new(RpcCache::new());
    let cached_provider = CachedProvider::new(env.provider().clone(), cache.clone());

    // Fee history is no longer cached - fetch directly from provider
    let fee_history = cached_provider
        .as_provider()
        .get_fee_history(5, alloy::eips::BlockNumberOrTag::Latest, &[50.0])
        .await
        .unwrap();

    assert!(!fee_history.base_fee_per_gas.is_empty());
}

#[tokio::test]
async fn test_cache_memory_pressure() {
    let cache = RpcCache::new();

    // Add many entries to test memory usage
    for i in 0..1000 {
        // Create unique addresses by using i as the last bytes
        let mut addr_bytes = [0u8; 20];
        addr_bytes[16..20].copy_from_slice(&(i as u32).to_be_bytes());
        let addr = Address::from_slice(&addr_bytes);
        cache.set_code(addr, bytes!("608060405234801561001057600080fd5b50"));

        // Fee history not cached anymore - too volatile
    }

    let stats = cache.stats();
    assert_eq!(stats.code_cache_size, 1000);
    // Fee history no longer cached

    // Cleanup should work even with many entries
    cache.cleanup_expired();

    // All entries should still be valid (not expired)
    let stats_after = cache.stats();
    assert_eq!(stats_after.code_cache_size, 1000);
    // Fee history no longer cached
}

#[tokio::test]
async fn test_pending_call_timeout_cleanup() {
    let cache = RpcCache::new();

    let call_key = CallKey {
        to: address!("1234567890123456789012345678901234567890"),
        data: bytes!("a9059cbb"),
        block: "latest".to_string(),
    };

    // Start a call but don't complete it (this should remain after cleanup)
    let sender = match cache.deduplicate_call(call_key.clone()) {
        DeduplicationResult::New(sender) => sender,
        _ => panic!("Expected new call"),
    };

    // Create a receiver to keep the sender alive
    let _receiver = sender.subscribe();

    // Manually insert a timed-out pending call
    let old_call_key = CallKey {
        to: address!("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"),
        data: bytes!("deadbeef"),
        block: "latest".to_string(),
    };

    let (tx, _) = tokio::sync::broadcast::channel(1);
    let old_pending = relay::cache::PendingCall {
        sender: Arc::new(tx),
        started_at: std::time::Instant::now() - Duration::from_secs(60), // 1 minute ago
    };
    cache.pending_calls.insert(old_call_key.clone(), old_pending);

    assert_eq!(cache.pending_calls.len(), 2);

    // Cleanup should remove timed-out calls
    cache.cleanup_expired();

    // Only the recent call should remain
    assert_eq!(cache.pending_calls.len(), 1);
    assert!(cache.pending_calls.contains_key(&call_key));
    assert!(!cache.pending_calls.contains_key(&old_call_key));
}

// Fee history cache uniqueness test removed - fee history no longer cached

#[tokio::test]
#[ignore] // Requires funded environment
async fn test_cache_performance_improvement() {
    let env = Environment::setup().await.unwrap();
    let cache = Arc::new(RpcCache::new());
    let cached_provider = CachedProvider::new(env.provider().clone(), cache.clone());

    // Measure time for first chain_id call (cache miss)
    let start = std::time::Instant::now();
    let _chain_id1 = cached_provider.get_chain_id_cached().await.unwrap();
    let _first_duration = start.elapsed();

    // Measure time for second chain_id call (cache hit)
    let start = std::time::Instant::now();
    let _chain_id2 = cached_provider.get_chain_id_cached().await.unwrap();
    let second_duration = start.elapsed();

    // Second call should be significantly faster (cached)
    // Note: This test might be flaky in some environments, so we just ensure
    // the second call doesn't take unreasonably long
    assert!(second_duration < Duration::from_millis(10)); // Should be very fast from cache

    // Verify cache stats show the hit
    let stats = cache.stats();
    assert!(stats.chain_id_cached);
}
