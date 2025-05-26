use alloy_primitives::{Address, U256};
use relay::{
    rpc::RelayApiClient, signers::Eip712PayLoadSigner, types::{
        rpc::{Meta, PrepareCallsCapabilities, PrepareCallsParameters}, KeyType, KeyWith712Signer
    }
};
use relay::types::Call;
use tracing_subscriber::EnvFilter;
use crate::e2e::{await_calls_status, cases::prep_account, environment::Environment, send_prepared_calls};

/// Ensures we are getting paid correctly
#[tokio::test(flavor = "multi_thread")]
async fn ensure_valid_fees() -> eyre::Result<()> {
    tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).init();
    let mut env = Environment::setup_with_prep().await?;

    let admin_key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();

    prep_account(&mut env, &[&admin_key]).await?;

    // Create PreCall with the upgrade call
    let response = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            from: Some(env.eoa.address()),
            calls: (1..40).map(|_| Call {
                to: Address::ZERO,
                value: U256::ZERO,
                data: Default::default(),
            }).collect(),
            chain_id: env.chain_id,
            capabilities: PrepareCallsCapabilities {
                authorize_keys: vec![],
                revoke_keys: vec![],
                meta: Meta { fee_payer: None, fee_token: env.fee_token, nonce: None },
                pre_calls: vec![],
                pre_call: false,
            },
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

    Ok(())
}
