use crate::e2e::{
    AuthKind, await_calls_status,
    cases::upgrade::upgrade_account_lazily,
    environment::{Environment, EnvironmentConfig, mint_erc20s},
    send_prepared_calls,
};
use alloy::{
    primitives::{Address, U64, U256},
    providers::{Provider, ext::AnvilApi},
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use relay::{
    provider::ProviderExt,
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    types::{
        AssetUid, Call, IERC20, KeyType, KeyWith712Signer,
        rpc::{Meta, PrepareCallsCapabilities, PrepareCallsParameters},
    },
};

/// Ensures we are getting paid correctly
#[tokio::test(flavor = "multi_thread")]
async fn ensure_valid_fees() -> eyre::Result<()> {
    let fee_recipient = Address::random();
    let env = Environment::setup_with_config(EnvironmentConfig {
        fee_recipient,
        num_signers: 1,
        ..Default::default()
    })
    .await?;

    let signer = env.signers[0].clone();
    let admin_key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();

    upgrade_account_lazily(&env, &[admin_key.to_authorized()], AuthKind::Auth).await?;

    let fee_token_decimals = env.provider().get_token_decimals(env.fee_token).await?;

    let fee_recipient_balance_before =
        IERC20::new(env.fee_token, env.provider()).balanceOf(fee_recipient).call().await?;
    let signer_balance_before = env.provider().get_balance(signer.address()).await?;

    // Create PreCall with the upgrade call
    let mut rng = StdRng::seed_from_u64(1337);
    let num_calls = rng.random_range(2..100);
    let response = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            from: Some(env.eoa.address()),
            calls: (1..num_calls)
                .map(|_| Call { to: Address::ZERO, value: U256::ZERO, data: Default::default() })
                .collect(),
            chain_id: env.chain_id(),
            capabilities: PrepareCallsCapabilities {
                authorize_keys: vec![],
                revoke_keys: vec![],
                meta: Meta { fee_payer: None, fee_token: Some(env.fee_token), nonce: None },
                pre_calls: vec![],
                pre_call: false,
                required_funds: vec![],
            },
            state_overrides: Default::default(),
            balance_overrides: Default::default(),
            key: Some(admin_key.to_call_key()),
        })
        .await?;

    let bundle_id = send_prepared_calls(
        &env,
        &admin_key,
        admin_key.sign_payload_hash(response.digest).await?,
        response.context,
    )
    .await?;

    // Wait for bundle to not be pending.
    let status = await_calls_status(&env, bundle_id).await?;
    assert!(status.status.is_confirmed(), "{status:?}");

    let fee_recipient_balance_after =
        IERC20::new(env.fee_token, env.provider()).balanceOf(fee_recipient).call().await?;
    let signer_balance_after = env.provider().get_balance(signer.address()).await?;

    let eth_paid = signer_balance_before - signer_balance_after;
    let fee_received = fee_recipient_balance_after - fee_recipient_balance_before;

    let uid = env
        .relay_endpoint
        .get_capabilities(Some(vec![U64::from(env.chain_id())]))
        .await?
        .chain(env.chain_id())
        .fees
        .tokens
        .iter()
        .find_map(|t| (t.asset.address == env.fee_token).then_some(t.uid.clone()))
        .unwrap();

    let fee_token_price = env
        .relay_handle
        .price_oracle
        .native_conversion_rate(uid, AssetUid::new("eth".into()))
        .await
        .unwrap();

    let expected_fee =
        eth_paid * U256::from(10u128.pow(fee_token_decimals as u32)) / fee_token_price;

    assert!(fee_received >= expected_fee);

    Ok(())
}

/// Tests that fee token is automatically selected when not specified
#[tokio::test(flavor = "multi_thread")]
async fn auto_select_fee_token() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    // Mint fee tokens to the EOA so it has a significant balance for auto-selection
    // Use the helper which handles test tokens properly (mints 100M tokens each time)
    for _ in 0..5 {
        mint_erc20s(&[env.fee_token], &[env.eoa.address()], env.provider()).await?;
    }

    // Also ensure the EOA has some native ETH balance for comparison
    env.provider()
        .anvil_set_balance(env.eoa.address(), U256::from(10).pow(U256::from(18))) // 1 ETH
        .await?;

    // Create and authorize a key
    let admin_key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();
    upgrade_account_lazily(&env, &[admin_key.to_authorized()], AuthKind::Auth).await?;

    let response = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            from: Some(env.eoa.address()),
            calls: vec![Call::transfer(env.erc20, Address::ZERO, U256::from(100))],
            chain_id: env.chain_id(),
            capabilities: PrepareCallsCapabilities {
                authorize_keys: vec![],
                meta: Meta {
                    fee_payer: None,
                    fee_token: None, // Not specifying fee token - relay should auto-select
                    nonce: None,
                },
                revoke_keys: vec![],
                pre_calls: vec![],
                pre_call: false,
                required_funds: vec![],
            },
            state_overrides: Default::default(),
            balance_overrides: Default::default(),
            key: Some(admin_key.to_call_key()),
        })
        .await?;

    // Verify that the fee token was auto-selected to be env.fee_token (since we gave it a very high
    // balance)
    let quote = response.context.quote().expect("Should have quote context");
    assert_eq!(
        quote.ty().quotes[0].intent.payment_token(),
        env.fee_token,
        "Should have selected the fee token with highest USD value"
    );

    Ok(())
}
