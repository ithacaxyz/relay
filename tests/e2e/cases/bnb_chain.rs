use crate::e2e::{
    AuthKind, Environment,
    cases::upgrade::upgrade_account_eagerly,
};
use alloy::primitives::{Address, U256};
use relay::{
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    types::{
        Call, CoinKind, KeyType, KeyWith712Signer,
        rpc::{Meta, PrepareCallsCapabilities, PrepareCallsParameters},
    },
};

#[tokio::test(flavor = "multi_thread")]
#[ignore] // Run with: TEST_FORK_URL=https://binance.llamarpc.com cargo test test_bnb_asset_diff_symbols -- --ignored --nocapture
async fn test_bnb_asset_diff_symbols() -> eyre::Result<()> {
    // Test native BNB to verify symbol handling on BSC chain
    let env = Environment::setup().await?.with_native_payment();
    
    println!("\n🔍 Testing BNB asset diff symbols on BSC chain");
    println!("   Chain ID: {} (forked from BSC)", env.chain_id());
    
    // Setup account
    let admin_key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    upgrade_account_eagerly(&env, &[admin_key.to_authorized()], &admin_key, AuthKind::Auth).await?;
    
    // Test with native BNB (Address::ZERO)
    println!("\n📊 Testing with native BNB fee token (Address::ZERO)");
    
    // Create a transfer that will use native BNB for fees
    let recipient = Address::from([1u8; 20]);
    let value = U256::from(1_000_000_000_000_000u64); // 0.001 BNB
    
    let call = Call {
        to: recipient,
        value,
        data: vec![].into(),
    };
    
    let params = PrepareCallsParameters {
        from: Some(env.eoa.address()),
        calls: vec![call],
        chain_id: env.chain_id(),
        capabilities: PrepareCallsCapabilities {
            meta: Meta { 
                fee_payer: None, 
                fee_token: Address::ZERO, // Native BNB
                nonce: None 
            },
            authorize_keys: vec![],
            revoke_keys: vec![],
            pre_calls: vec![],
            pre_call: false,
            required_funds: vec![],
        },
        state_overrides: Default::default(),
        balance_overrides: Default::default(),
        key: Some(admin_key.to_call_key()),
    };
    
    let response = env.relay_endpoint.prepare_calls(params).await?;
    
    // Analyze asset diffs and verify BNB symbol
    let mut found_native_bnb = false;
    if let Some(asset_diffs) = response.capabilities.asset_diff.asset_diffs.get(&env.chain_id()) {
        println!("\n💎 Asset diffs found:");
        for (address, diffs) in &asset_diffs.0 {
            for diff in diffs {
                if diff.address.is_none() { // Native token
                    found_native_bnb = true;
                    
                    println!("   Native token for address {address}:");
                    println!("     Symbol: {:?}", diff.metadata.symbol);
                    println!("     Value: {} wei", diff.value);
                    println!("     Direction: {:?}", diff.direction);
                    println!("     Decimals: {:?}", diff.metadata.decimals);
                    
                    // ASSERTION: Verify the native token symbol is "BNB" on BSC
                    assert_eq!(
                        diff.metadata.symbol.as_deref(),
                        Some("BNB"),
                        "Native token on BSC chain should have symbol 'BNB', got {:?}",
                        diff.metadata.symbol
                    );
                    
                    // Verify decimals are correct for BNB
                    assert_eq!(
                        diff.metadata.decimals,
                        Some(18),
                        "BNB should have 18 decimals"
                    );
                    
                    // Check if fiat value is present
                    if let Some(fiat) = &diff.fiat {
                        println!("     USD value: ${}", fiat.value);
                        assert_eq!(fiat.currency, "usd", "Fiat currency should be USD");
                    }
                }
            }
        }
    }
    
    // Ensure we found native BNB in the asset diffs
    assert!(
        found_native_bnb,
        "Should have found native BNB in asset diffs"
    );
    
    // Check fee USD calculation
    if let Some(fee_total) = response.capabilities.asset_diff.fee_totals.get(&env.chain_id()) {
        println!("\n💵 Fee calculation:");
        println!("   Fee in USD: ${}", fee_total.value);
        println!("   Currency: {}", fee_total.currency);
        
        assert_eq!(
            fee_total.currency, "usd",
            "Fee currency should be USD"
        );
    }
    
    println!("\n✅ BNB asset diff symbols test passed!");
    println!("   ✓ Native token correctly identified as BNB");
    println!("   ✓ Symbol assertion passed");
    println!("   ✓ Decimals verified (18)");
    
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore] // Run with: TEST_FORK_URL=https://binance.llamarpc.com GECKO_API=<key> cargo test test_bnb_usd_price -- --ignored --nocapture
async fn test_bnb_usd_price() -> eyre::Result<()> {
    use relay::types::CoinKind;
    
    let env = Environment::setup().await?.with_native_payment();
    
    println!("\n💵 Testing BNB USD price calculation");
    
    // Check if price oracle has BNB price
    let oracle = &env.relay_handle.price_oracle;
    // Try to get BNB USD price
    let bnb_usd = oracle.usd_price(CoinKind::BNB).await;
    
    if let Some(price) = bnb_usd {
        println!("   BNB USD price: ${price}");
        assert!(price > 0.0, "BNB price should be positive");
    } else {
        println!("   ⚠️  BNB USD price not available (need GECKO_API set)");
    }
    
    // Also check ETH price for comparison
    let eth_usd = oracle.usd_price(CoinKind::ETH).await;
    if let Some(price) = eth_usd {
        println!("   ETH USD price: ${price}");
    }
    
    // Setup account for transaction test
    let admin_key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    upgrade_account_eagerly(&env, &[admin_key.to_authorized()], &admin_key, AuthKind::Auth).await?;
    
    // Create transaction with native BNB fee
    let params = PrepareCallsParameters {
        from: Some(env.eoa.address()),
        calls: vec![Call {
            to: Address::from([2u8; 20]),
            value: U256::from(1_000_000_000_000_000u64), // 0.001 BNB
            data: vec![].into(),
        }],
        chain_id: env.chain_id(),
        capabilities: PrepareCallsCapabilities {
            meta: Meta { 
                fee_payer: None, 
                fee_token: Address::ZERO, // Native BNB
                nonce: None 
            },
            authorize_keys: vec![],
            revoke_keys: vec![],
            pre_calls: vec![],
            pre_call: false,
            required_funds: vec![],
        },
        state_overrides: Default::default(),
        balance_overrides: Default::default(),
        key: Some(admin_key.to_call_key()),
    };
    
    let response = env.relay_endpoint.prepare_calls(params).await?;
    
    // Check if fee USD is calculated
    if let Some(fee_total) = response.capabilities.asset_diff.fee_totals.get(&env.chain_id()) {
        println!("\n📊 Transaction fee:");
        if let Some(quotes) = response.context.quote() {
            if let Some(quote) = quotes.ty().quotes.first() {
                println!("   Payment amount: {} wei", quote.intent.totalPaymentAmount);
                println!("   Fee token: {:?}", quote.intent.paymentToken);
            }
        }
        println!("   Fee in USD: ${}", fee_total.value);
        
        // Verify fee USD is reasonable (should be > 0)
        assert!(fee_total.value > 0.0, "Fee USD should be positive when price oracle is configured");
    } else {
        println!("\n⚠️  Fee USD not calculated (price oracle may not be configured)");
    }
    
    println!("\n✅ BNB USD price test passed!");
    Ok(())
}