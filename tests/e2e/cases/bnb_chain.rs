use crate::e2e::{AuthKind, Environment, cases::upgrade::upgrade_account_eagerly};
use alloy::primitives::{Address, U256};
use relay::{
    rpc::RelayApiClient,
    types::{
        Call, KeyType, KeyWith712Signer,
        rpc::{Meta, PrepareCallsCapabilities, PrepareCallsParameters},
    },
};
use tracing::info;

#[tokio::test(flavor = "multi_thread")]
#[ignore] // Run with: TEST_FORK_URL=https://binance.llamarpc.com cargo test test_bnb_asset_diff_symbols -- --ignored --nocapture
async fn test_bnb_asset_diff_symbols() -> eyre::Result<()> {
    // Test native BNB to verify symbol handling on BSC chain
    let env = Environment::setup().await?.with_native_payment();

    info!("\n🔍 Testing BNB asset diff symbols on BSC chain");
    info!("   Chain ID: {} (forked from BSC)", env.chain_id());

    // Setup account
    let admin_key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    upgrade_account_eagerly(&env, &[admin_key.to_authorized()], &admin_key, AuthKind::Auth).await?;

    // Test with native BNB (Address::ZERO)
    info!("\n📊 Testing with native BNB fee token (Address::ZERO)");

    // Create a transfer that will use native BNB for fees
    let recipient = Address::from([1u8; 20]);
    let value = U256::from(1_000_000_000_000_000u64); // 0.001 BNB

    let call = Call { to: recipient, value, data: vec![].into() };

    let params = PrepareCallsParameters {
        from: Some(env.eoa.address()),
        calls: vec![call],
        chain_id: env.chain_id(),
        capabilities: PrepareCallsCapabilities {
            meta: Meta {
                fee_payer: None,
                fee_token: Address::ZERO, // Native BNB
                nonce: None,
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
        info!("\n💎 Asset diffs found:");
        for (address, diffs) in &asset_diffs.0 {
            for diff in diffs {
                if diff.address.is_none() {
                    // Native token
                    found_native_bnb = true;

                    info!("   Native token for address {address}:");
                    info!("     Symbol: {:?}", diff.metadata.symbol);
                    info!("     Value: {} wei", diff.value);
                    info!("     Direction: {:?}", diff.direction);
                    info!("     Decimals: {:?}", diff.metadata.decimals);

                    // ASSERTION: Verify the native token symbol is "BNB" on BSC
                    assert_eq!(
                        diff.metadata.symbol.as_deref(),
                        Some("BNB"),
                        "Native token on BSC chain should have symbol 'BNB', got {:?}",
                        diff.metadata.symbol
                    );

                    // Verify decimals are correct for BNB
                    assert_eq!(diff.metadata.decimals, Some(18), "BNB should have 18 decimals");

                    // Check if fiat value is present
                    if let Some(fiat) = &diff.fiat {
                        info!("     USD value: ${}", fiat.value);
                        assert_eq!(fiat.currency, "usd", "Fiat currency should be USD");
                    }
                }
            }
        }
    }

    // Ensure we found native BNB in the asset diffs
    assert!(found_native_bnb, "Should have found native BNB in asset diffs");

    // Check fee USD calculation
    if let Some(fee_total) = response.capabilities.asset_diff.fee_totals.get(&env.chain_id()) {
        info!("\n💵 Fee calculation:");
        info!("   Fee in USD: ${}", fee_total.value);
        info!("   Currency: {}", fee_total.currency);

        assert_eq!(fee_total.currency, "usd", "Fee currency should be USD");
    }

    info!("\n✅ BNB asset diff symbols test passed!");
    info!("   ✓ Native token correctly identified as BNB");
    info!("   ✓ Symbol assertion passed");
    info!("   ✓ Decimals verified (18)");

    Ok(())
}
