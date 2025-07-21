use crate::e2e::{
    AuthKind, await_calls_status,
    cases::upgrade::upgrade_account_lazily,
    environment::{Environment, EnvironmentConfig},
    send_prepared_calls,
};
use alloy::providers::Provider;
use alloy_primitives::{Address, U256};
use rand::{Rng, SeedableRng, rngs::StdRng};
use relay::{
    config::TransactionServiceConfig,
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    types::{
        Call, IERC20, KeyType, KeyWith712Signer,
        rpc::{Meta, PrepareCallsCapabilities, PrepareCallsParameters},
    },
};

/// Ensures we are getting paid correctly
#[tokio::test(flavor = "multi_thread")]
async fn ensure_valid_fees() -> eyre::Result<()> {
    let fee_recipient = Address::random();
    let env = Environment::setup_with_config(EnvironmentConfig {
        fee_recipient,
        transaction_service_config: TransactionServiceConfig {
            num_signers: 1,
            ..Default::default()
        },
        ..Default::default()
    })
    .await?;

    let signer = env.signers[0].clone();
    let admin_key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();

    upgrade_account_lazily(&env, &[admin_key.to_authorized()], AuthKind::Auth).await?;

    let fee_token_decimals = IERC20::new(env.fee_token, env.provider()).decimals().call().await?;

    let fee_recipient_balance_before =
        IERC20::new(env.fee_token, env.provider()).balanceOf(fee_recipient).call().await?;
    let signer_balance_before = env.provider().get_balance(signer.address()).await?;

    // Create PreCall with the upgrade call
    let mut rng = StdRng::seed_from_u64(1337);
    let num_calls = rng.random_range(2..100);
    let response = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            required_funds: vec![],
            from: Some(env.eoa.address()),
            calls: (1..num_calls)
                .map(|_| Call { to: Address::ZERO, value: U256::ZERO, data: Default::default() })
                .collect(),
            chain_id: env.chain_id(),
            capabilities: PrepareCallsCapabilities {
                authorize_keys: vec![],
                revoke_keys: vec![],
                meta: Meta { fee_payer: None, fee_token: env.fee_token, nonce: None },
                pre_calls: vec![],
                pre_call: false,
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

    let kind = env
        .relay_endpoint
        .get_capabilities(vec![env.chain_id()])
        .await?
        .chain(env.chain_id())
        .fees
        .tokens
        .iter()
        .find_map(|t| (t.address == env.fee_token).then_some(t.kind))
        .unwrap();

    let fee_token_price = env.relay_handle.price_oracle.eth_price(kind).await.unwrap();

    let expected_fee =
        eth_paid * U256::from(10u128.pow(fee_token_decimals as u32)) / fee_token_price;

    assert!(fee_received >= expected_fee);

    Ok(())
}
