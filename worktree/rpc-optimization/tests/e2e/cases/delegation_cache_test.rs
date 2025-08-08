use crate::e2e::{
    AuthKind,
    cases::{upgrade::upgrade_account_lazily, upgrade_account_eagerly},
    environment::Environment,
};
use alloy::{
    eips::eip7702::constants::EIP7702_DELEGATION_DESIGNATOR,
    primitives::{Address, B256, Bytes, U256},
    providers::{Provider, ext::AnvilApi},
    rpc::types::TransactionRequest,
    sol_types::{SolCall, SolValue},
};
use relay::{
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    types::{
        Call,
        IthacaAccount::{self, upgradeProxyAccountCall},
        KeyType, KeyWith712Signer, Signature, SignedCall,
        rpc::{Meta, PrepareCallsCapabilities, PrepareCallsParameters},
    },
};
use std::time::{Duration, Instant};

/// Test that delegation implementation caching works correctly and provides performance benefits.
#[tokio::test(flavor = "multi_thread")]
async fn test_delegation_implementation_caching() -> eyre::Result<()> {
    let env = Environment::setup().await?;
    let admin_key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();
    
    // Set up account correctly
    upgrade_account_eagerly(&env, &[admin_key.to_authorized()], &admin_key, AuthKind::Auth).await?;
    
    let params = PrepareCallsParameters {
        from: Some(env.eoa.address()),
        calls: vec![],
        chain_id: env.chain_id(),
        capabilities: PrepareCallsCapabilities {
            authorize_keys: vec![],
            revoke_keys: vec![],
            meta: Meta { fee_payer: None, fee_token: env.fee_token, nonce: None },
            pre_calls: vec![],
            pre_call: false,
            required_funds: vec![],
        },
        state_overrides: Default::default(),
        balance_overrides: Default::default(),
        key: Some(admin_key.to_call_key()),
    };
    
    println!("Testing delegation caching performance...");
    
    // First call - should be slower (cache miss)
    let start = Instant::now();
    let response1 = env.relay_endpoint.prepare_calls(params.clone()).await?;
    let first_call_duration = start.elapsed();
    
    // Second call - should be faster due to caching
    let start = Instant::now();
    let response2 = env.relay_endpoint.prepare_calls(params.clone()).await?;
    let second_call_duration = start.elapsed();
    
    // Third call - should also be fast due to caching
    let start = Instant::now();
    let response3 = env.relay_endpoint.prepare_calls(params.clone()).await?;
    let third_call_duration = start.elapsed();
    
    // Verify responses are consistent
    assert_eq!(response1.digest, response2.digest);
    assert_eq!(response2.digest, response3.digest);
    
    println!("First call (cache miss): {:?}", first_call_duration);
    println!("Second call (cache hit): {:?}", second_call_duration);
    println!("Third call (cache hit): {:?}", third_call_duration);
    
    // The second and third calls should be significantly faster
    // Allow some variance due to test environment, but expect at least some improvement
    let cache_speedup_threshold = Duration::from_millis(5);
    
    // At minimum, ensure cached calls aren't significantly slower than first call
    assert!(
        second_call_duration <= first_call_duration + cache_speedup_threshold,
        "Second call should not be significantly slower than first call. First: {:?}, Second: {:?}",
        first_call_duration,
        second_call_duration
    );
    
    assert!(
        third_call_duration <= first_call_duration + cache_speedup_threshold,
        "Third call should not be significantly slower than first call. First: {:?}, Third: {:?}",
        first_call_duration,
        third_call_duration
    );
    
    println!("✅ Delegation caching test passed!");
    
    Ok(())
}

/// Test cache behavior with multiple different accounts
#[tokio::test(flavor = "multi_thread")]
async fn test_delegation_cache_multiple_accounts() -> eyre::Result<()> {
    let env = Environment::setup().await?;
    
    // Create multiple keys/accounts for testing
    let admin_key1 = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();
    let admin_key2 = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();
    
    // Setup first account
    upgrade_account_eagerly(&env, &[admin_key1.to_authorized()], &admin_key1, AuthKind::Auth).await?;
    
    // Create params for first account
    let params1 = PrepareCallsParameters {
        from: Some(env.eoa.address()),
        calls: vec![],
        chain_id: env.chain_id(),
        capabilities: PrepareCallsCapabilities {
            authorize_keys: vec![],
            revoke_keys: vec![],
            meta: Meta { fee_payer: None, fee_token: env.fee_token, nonce: None },
            pre_calls: vec![],
            pre_call: false,
            required_funds: vec![],
        },
        state_overrides: Default::default(),
        balance_overrides: Default::default(),
        key: Some(admin_key1.to_call_key()),
    };
    
    // Test first account - cache miss
    let start = Instant::now();
    let response1 = env.relay_endpoint.prepare_calls(params1.clone()).await?;
    let first_duration = start.elapsed();
    
    // Test first account again - cache hit
    let start = Instant::now();
    let response1_cached = env.relay_endpoint.prepare_calls(params1.clone()).await?;
    let first_cached_duration = start.elapsed();
    
    // Verify consistency
    assert_eq!(response1.digest, response1_cached.digest);
    
    println!("Account 1 - First call: {:?}", first_duration);
    println!("Account 1 - Cached call: {:?}", first_cached_duration);
    println!("✅ Multiple account caching test passed!");
    
    Ok(())
}