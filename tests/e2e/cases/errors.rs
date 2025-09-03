use crate::e2e::{AuthKind, cases::upgrade_account_eagerly, environment::Environment};
use alloy::primitives::{Address, U256};
use relay::{
    rpc::RelayApiClient,
    types::{
        Call, KeyType, KeyWith712Signer,
        rpc::{Meta, PrepareCallsCapabilities, PrepareCallsParameters},
    },
};

#[tokio::test(flavor = "multi_thread")]
async fn decode_insufficient_allowance() -> eyre::Result<()> {
    let env = Environment::setup().await?;
    let key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();

    upgrade_account_eagerly(&env, &[key.to_authorized()], &key, AuthKind::Auth).await?;

    let response = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            from: Some(env.eoa.address()),
            calls: vec![Call::transfer_from(
                env.erc20s[4],
                Address::ZERO,
                env.eoa.address(),
                U256::from(10000000u64),
            )],
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
            key: Some(key.to_call_key()),
        })
        .await;

    assert!(response.is_err_and(|err| err.to_string().contains("InsufficientAllowance")));

    Ok(())
}
