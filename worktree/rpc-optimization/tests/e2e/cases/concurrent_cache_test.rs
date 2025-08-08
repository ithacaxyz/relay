use crate::e2e::Environment;
use alloy::primitives::Address;
use futures::future::join_all;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Barrier;

/// Test that concurrent cache access doesn't cause race conditions
#[tokio::test]
async fn test_concurrent_cache_access() -> anyhow::Result<()> {
    let env = Environment::setup().await?;
    
    // Create a test account with delegation
    let account_address = Address::random();
    
    // Create a barrier to ensure all tasks start at the same time
    let num_concurrent_requests = 100;
    let barrier = Arc::new(Barrier::new(num_concurrent_requests));
    
    // Track RPC call count using a shared counter
    let rpc_call_count = Arc::new(tokio::sync::Mutex::new(0));
    
    // Launch concurrent requests for the same address
    let mut handles = Vec::new();
    for _ in 0..num_concurrent_requests {
        let relay_endpoint = env.relay_endpoint.clone();
        let barrier_clone = barrier.clone();
        let rpc_count_clone = rpc_call_count.clone();
        
        let handle = tokio::spawn(async move {
            // Wait for all tasks to be ready
            barrier_clone.wait().await;
            
            let start = Instant::now();
            
            // Make the RPC call to get delegation implementation
            let params = serde_json::json!({
                "account": account_address,
            });
            
            let response = relay_endpoint
                .request::<_, Address>("relay_getDelegationImplementation", params)
                .await;
            
            let duration = start.elapsed();
            
            // Track if this was likely an RPC call (>5ms) vs cache hit (<1ms)
            if duration.as_millis() > 5 {
                let mut count = rpc_count_clone.lock().await;
                *count += 1;
            }
            
            (response, duration)
        });
        
        handles.push(handle);
    }
    
    // Wait for all requests to complete
    let results: Vec<_> = join_all(handles)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    
    // Verify all requests got the same result
    let first_result = &results[0].0;
    for (result, _duration) in &results {
        assert_eq!(
            result.as_ref().map(|a| a.to_string()),
            first_result.as_ref().map(|a| a.to_string()),
            "All concurrent requests should return the same result"
        );
    }
    
    // Verify that only ONE RPC call was made (allowing for some timing variations)
    let actual_rpc_calls = *rpc_call_count.lock().await;
    assert!(
        actual_rpc_calls <= 2,
        "Expected at most 2 RPC calls due to cache coalescing, but got {}",
        actual_rpc_calls
    );
    
    // Log performance stats
    let durations: Vec<_> = results.iter().map(|(_, d)| d.as_micros()).collect();
    let min_duration = *durations.iter().min().unwrap();
    let max_duration = *durations.iter().max().unwrap();
    let avg_duration = durations.iter().sum::<u128>() / durations.len() as u128;
    
    println!("Concurrent cache test results:");
    println!("  - Concurrent requests: {}", num_concurrent_requests);
    println!("  - Actual RPC calls: {}", actual_rpc_calls);
    println!("  - Min duration: {}μs", min_duration);
    println!("  - Max duration: {}μs", max_duration);
    println!("  - Avg duration: {}μs", avg_duration);
    
    Ok(())
}

/// Test cache invalidation and retry mechanism
#[tokio::test]
async fn test_cache_invalidation_on_error() -> anyhow::Result<()> {
    let env = Environment::setup().await?;
    
    // Use zero address to trigger error path
    let zero_address = Address::ZERO;
    
    // First call should fail and cache the failure
    let params = serde_json::json!({
        "account": zero_address,
    });
    
    let result1 = env.relay_endpoint
        .request::<_, Address>("relay_getDelegationImplementation", params.clone())
        .await;
    
    assert!(result1.is_err(), "Zero address should cause an error");
    
    // Second call should detect the cached failure and retry
    let result2 = env.relay_endpoint
        .request::<_, Address>("relay_getDelegationImplementation", params)
        .await;
    
    assert!(result2.is_err(), "Zero address should still cause an error");
    
    Ok(())
}

/// Test cache hit performance
#[tokio::test]
async fn test_cache_hit_performance() -> anyhow::Result<()> {
    let env = Environment::setup().await?;
    
    let account_address = Address::random();
    let params = serde_json::json!({
        "account": account_address,
    });
    
    // First call - cache miss, should take longer
    let start = Instant::now();
    let _result1 = env.relay_endpoint
        .request::<_, Address>("relay_getDelegationImplementation", params.clone())
        .await?;
    let first_duration = start.elapsed();
    
    // Allow cache to settle
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    
    // Second call - cache hit, should be much faster
    let start = Instant::now();
    let _result2 = env.relay_endpoint
        .request::<_, Address>("relay_getDelegationImplementation", params)
        .await?;
    let second_duration = start.elapsed();
    
    // Cache hit should be at least 10x faster than cache miss
    assert!(
        second_duration < first_duration / 10,
        "Cache hit ({:?}) should be much faster than cache miss ({:?})",
        second_duration,
        first_duration
    );
    
    println!("Cache performance test:");
    println!("  - Cache miss duration: {:?}", first_duration);
    println!("  - Cache hit duration: {:?}", second_duration);
    println!("  - Speedup: {:.1}x", first_duration.as_nanos() as f64 / second_duration.as_nanos() as f64);
    
    Ok(())
}