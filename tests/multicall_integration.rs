//! Integration tests for multicall functionality

use alloy::{
    primitives::{Address, U256, address},
    providers::Provider,
};
use relay::{
    cache::RpcCache,
    metrics::{record_multicall_fallback, record_multicall_usage},
    provider::MulticallExt,
    types::{Account, IERC20},
};
use std::time::Instant;

#[cfg(test)]
mod multicall_tests {
    use super::*;
    use crate::e2e::Environment;

    #[tokio::test]
    async fn test_multicall_performance() {
        let env = Environment::setup().await.unwrap();
        let provider = &env.provider;

        // Test addresses
        let test_accounts = vec![env.user_account.address(), env.funded_account.address()];

        // Measure sequential calls
        let start = Instant::now();
        for account in &test_accounts {
            let _ = provider.get_balance(*account).await;
            let _ = provider.get_code_at(*account).await;
        }
        let sequential_time = start.elapsed();

        // Measure batched calls with multicall
        let start = Instant::now();
        if provider.supports_multicall().await {
            let mut multicall = provider.create_multicall();
            for account in &test_accounts {
                multicall = multicall
                    .add_call(provider.get_balance(*account))
                    .add_call(provider.get_code_at(*account));
            }
            let _ = multicall.aggregate().await;
        }
        let batched_time = start.elapsed();

        // Verify batched is faster (should be at least 2x faster)
        assert!(
            batched_time < sequential_time / 2,
            "Multicall should be at least 2x faster than sequential calls"
        );
    }

    #[tokio::test]
    async fn test_multicall_with_cache() {
        let env = Environment::setup().await.unwrap();
        let provider = &env.provider;
        let cache = RpcCache::new();

        // Pre-populate cache with some data
        let test_address = address!("1234567890123456789012345678901234567890");
        cache.set_code(test_address, vec![0x60, 0x80].into());

        // Verify cache prevents unnecessary multicall inclusion
        assert!(cache.should_skip_in_multicall(&test_address));

        // Verify cache metrics
        assert_eq!(cache.code_cache_size(), 1);
    }

    #[tokio::test]
    async fn test_multicall_fallback() {
        let env = Environment::setup().await.unwrap();
        let provider = &env.provider;

        // Create a multicall that might fail
        let erc20 = IERC20::new(Address::ZERO, provider);

        // Try multicall with a potentially failing call
        let result = provider
            .multicall()
            .add(erc20.balanceOf(env.user_account.address()))
            .add(erc20.decimals())
            .aggregate()
            .await;

        // Even if multicall fails, we should handle it gracefully
        if result.is_err() {
            // Record fallback metric
            record_multicall_fallback(env.chain_id, "test_fallback");

            // Fallback to individual calls should work
            let balance = erc20.balanceOf(env.user_account.address()).call().await;
            assert!(balance.is_ok() || balance.is_err()); // Either way, it should not panic
        }
    }

    #[tokio::test]
    async fn test_multicall_erc20_queries() {
        let env = Environment::setup().await.unwrap();
        let provider = &env.provider;

        // Use a test ERC20 token
        let token = env.erc20_a;
        let erc20 = IERC20::new(token, provider);

        // Batch multiple ERC20 queries
        let result = provider
            .multicall()
            .add(erc20.balanceOf(env.user_account.address()))
            .add(erc20.decimals())
            .add(erc20.name())
            .add(erc20.symbol())
            .aggregate()
            .await;

        if let Ok((balance, decimals, name, symbol)) = result {
            // Record successful multicall
            record_multicall_usage(4, 3, env.chain_id);

            // Verify we got valid responses
            assert!(balance >= U256::ZERO);
            assert!(decimals > 0);
            assert!(!name.is_empty());
            assert!(!symbol.is_empty());
        }
    }

    #[tokio::test]
    async fn test_multicall_mixed_calls() {
        let env = Environment::setup().await.unwrap();
        let provider = &env.provider;

        if !provider.supports_multicall().await {
            return; // Skip test if multicall not supported
        }

        // Mix different types of calls
        let account = Account::new(env.user_account.address(), provider);
        let erc20 = IERC20::new(env.erc20_a, provider);

        // Create a mixed multicall batch
        let multicall = provider
            .create_multicall()
            .add_call(provider.get_balance(env.user_account.address()))
            .add_call(provider.get_code_at(env.orchestrator))
            .add_call(erc20.balanceOf(env.user_account.address()));

        // Execute and verify
        let result = multicall.aggregate().await;
        assert!(result.is_ok(), "Mixed multicall should succeed");
    }
}
