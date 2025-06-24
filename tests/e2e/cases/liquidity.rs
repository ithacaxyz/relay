//! Multi-chain relay end-to-end test cases

use crate::e2e::{cases::upgrade_account_eagerly, *};
use alloy_primitives::U256;
use eyre::Result;
use relay::{
    liquidity::{
        RebalanceService,
        bridge::{Bridge, SimpleBridge},
    },
    types::{IERC20, KeyType},
};

#[tokio::test(flavor = "multi_thread")]
async fn test_liquidity_management() -> Result<()> {
    let env = Environment::setup_multi_chain(2).await?;

    let providers = env
        .relay_handle
        .chains
        .chain_ids_iter()
        .map(|chain_id| {
            (*chain_id, env.relay_handle.chains.get(*chain_id).unwrap().provider.clone())
        })
        .collect();
    let bridge = SimpleBridge::new(
        env.relay_handle.coin_registry.clone(),
        providers,
        env.signers[0].clone(),
        env.funder,
    );

    let signer = env.signers[0].clone();

    let rebalance_service = RebalanceService::new(
        &env.relay_handle.coin_registry,
        env.relay_handle.chains.interop().liquidity_tracker().clone(),
        vec![Box::new(bridge) as Box<dyn Bridge>],
    );

    let token = env.erc20;
    let provider_0 = env.provider_for(0);
    let provider_1 = env.provider_for(1);

    for _ in 0..10 {
        mint_erc20s(&[env.erc20], &[env.eoa.address(), signer.address()], &provider_0).await?;
        mint_erc20s(&[env.erc20], &[env.eoa.address(), signer.address()], &provider_1).await?;
    }

    let funder_balance_0 = IERC20::new(token, provider_0).balanceOf(env.funder).call().await?;
    let funder_balance_1 = IERC20::new(token, provider_1).balanceOf(env.funder).call().await?;
    let eoa_balance_1 = IERC20::new(token, provider_1).balanceOf(env.eoa.address()).call().await?;

    tokio::spawn(rebalance_service.into_future());

    // Create a key for signing
    let key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();

    // Account ugprade deployed onchain.
    upgrade_account_eagerly(&env, &[key.to_authorized()], &key, AuthKind::Auth).await?;

    // Prepare the calls on chain 3 with required funds
    let PrepareCallsResponse { context, digest, .. } = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            calls: vec![common_calls::transfer(env.erc20, env.eoa.address(), funder_balance_0)],
            chain_id: env.chain_id_for(1),
            from: Some(env.eoa.address()),
            capabilities: PrepareCallsCapabilities {
                authorize_keys: vec![],
                revoke_keys: vec![],
                meta: Meta { fee_payer: None, fee_token: Address::ZERO, nonce: None },
                pre_calls: vec![],
                pre_call: false,
            },
            key: Some(key.to_call_key()),
            required_funds: vec![(env.erc20, funder_balance_1 + eoa_balance_1)],
        })
        .await?;

    // Sign the digest
    let signature = key.sign_payload_hash(digest).await?;

    // Send prepared calls on chain 3
    let bundle_id = send_prepared_calls(&env, &key, signature, context).await?;
    let status = await_calls_status(&env, bundle_id).await?;
    assert!(status.status.is_confirmed());

    let funder_balance_1 = IERC20::new(token, provider_1).balanceOf(env.funder).call().await?;
    assert_eq!(funder_balance_1, U256::from(0));

    tokio::time::sleep(Duration::from_secs(5)).await;

    let funder_balance_1 = IERC20::new(token, provider_1).balanceOf(env.funder).call().await?;
    assert!(!funder_balance_1.is_zero());

    Ok(())
}
