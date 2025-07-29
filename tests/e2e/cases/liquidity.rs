//! Multi-chain relay end-to-end test cases

use crate::e2e::{cases::upgrade_account_eagerly, *};
use alloy_primitives::U256;
use eyre::Result;
use relay::{
    config::RebalanceServiceConfig,
    liquidity::bridge::SimpleBridgeConfig,
    types::{Call, IERC20, KeyType, rpc::RequiredAsset},
};

#[tokio::test(flavor = "multi_thread")]
async fn test_multi_chain_liquidity_management() -> Result<()> {
    let env = Environment::setup_with_config(EnvironmentConfig {
        num_chains: 2,
        rebalance_service_config: Some(RebalanceServiceConfig {
            binance: None,
            simple: Some(SimpleBridgeConfig { signer_key: DEPLOYER_PRIVATE_KEY.to_string() }),
            funder_owner_key: DEPLOYER_PRIVATE_KEY.to_string(),
        }),
        ..Default::default()
    })
    .await?;

    let signer = env.deployer.clone();

    let token = env.erc20;
    let provider_0 = env.provider_for(0);
    let provider_1 = env.provider_for(1);

    // Fund EOA on chain 0 and bridge on chain 1
    for _ in 0..10 {
        mint_erc20s(&[env.erc20], &[env.eoa.address()], provider_0).await?;
        mint_erc20s(&[env.erc20], &[signer.address()], provider_1).await?;
    }

    let funder_balance_0 = IERC20::new(token, provider_0).balanceOf(env.funder).call().await?;
    let funder_balance_1 = IERC20::new(token, provider_1).balanceOf(env.funder).call().await?;
    let eoa_balance_1 = IERC20::new(token, provider_1).balanceOf(env.eoa.address()).call().await?;

    // Create a key for signing
    let key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();

    // Account ugprade deployed onchain.
    upgrade_account_eagerly(&env, &[key.to_authorized()], &key, AuthKind::Auth).await?;

    // Prepare the calls on chain 1 with required funds
    let PrepareCallsResponse { context, digest, .. } = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            calls: vec![Call::transfer(env.erc20, env.eoa.address(), funder_balance_0)],
            chain_id: env.chain_id_for(1),
            from: Some(env.eoa.address()),
            capabilities: PrepareCallsCapabilities {
                authorize_keys: vec![],
                revoke_keys: vec![],
                meta: Meta { fee_payer: None, fee_token: Address::ZERO, nonce: None },
                pre_calls: vec![],
                pre_call: false,
                required_funds: vec![RequiredAsset::new(
                    env.erc20,
                    funder_balance_1 + eoa_balance_1,
                )],
            },
            key: Some(key.to_call_key()),
            state_overrides: Default::default(),
            balance_overrides: Default::default(),
        })
        .await?;

    // Sign the digest
    let signature = key.sign_payload_hash(digest).await?;

    // Send prepared calls on chain 1
    let bundle_id = send_prepared_calls(&env, &key, signature, context).await?;
    let status = await_calls_status(&env, bundle_id).await?;
    assert!(status.status.is_confirmed());

    // Assert that we've drained funder on chain 1
    let funder_balance_1 = IERC20::new(token, provider_1).balanceOf(env.funder).call().await?;
    assert_eq!(funder_balance_1, U256::from(0));

    // Wait for rebalance to complete
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Assert that we've refilled funder on chain 1
    let funder_balance_1 = IERC20::new(token, provider_1).balanceOf(env.funder).call().await?;
    assert!(!funder_balance_1.is_zero());

    Ok(())
}
