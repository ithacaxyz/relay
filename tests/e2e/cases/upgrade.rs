//! Account upgrade related end-to-end test cases

use crate::e2e::{AuthKind, await_calls_status, environment::Environment};
use alloy::{
    eips::eip7702::SignedAuthorization,
    primitives::{Address, Bytes},
    providers::{Provider, ext::AnvilApi},
};
use relay::{
    rpc::RelayApiClient,
    types::{
        KeyType, KeyWith712Signer,
        rpc::{
            AuthorizeKey, BundleId, PrepareUpgradeAccountParameters, UpgradeAccountCapabilities,
            UpgradeAccountParameters,
        },
    },
};

pub async fn upgrade_account(
    env: &Environment,
    authorize_keys: &[AuthorizeKey],
    auth: AuthKind,
) -> eyre::Result<(BundleId, SignedAuthorization)> {
    let response = env
        .relay_endpoint
        .prepare_upgrade_account(PrepareUpgradeAccountParameters {
            address: env.eoa.address(),
            chain_id: env.chain_id,
            capabilities: UpgradeAccountCapabilities {
                authorize_keys: authorize_keys.to_vec(),
                delegation: env.delegation,
                fee_payer: None,
                fee_token: env.fee_token,
            },
        })
        .await?;

    // Sign UserOp digest
    let signature = env.eoa.root_signer().sign_hash(&response.digest).await?;

    // Sign 7702 delegation
    let nonce = env.provider.get_transaction_count(env.eoa.address()).await?;
    let authorization = auth.sign(env, nonce).await?;

    // Upgrade account.
    let response = env
        .relay_endpoint
        .upgrade_account(UpgradeAccountParameters {
            context: response.context,
            signature,
            authorization: authorization.clone(),
        })
        .await?;

    // Check that transaction has been successful.
    let bundle_id = response.bundles[0].id;

    // Wait for bundle to not be pending.
    let status = await_calls_status(env, bundle_id).await?;

    assert!(status.status.is_final());

    Ok((bundle_id, authorization))
}

#[tokio::test(flavor = "multi_thread")]
async fn basic_upgrade() -> eyre::Result<()> {
    let env = Environment::setup_with_upgraded().await?;
    let key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();

    upgrade_account(&env, &[key.to_authorized(Some(env.eoa.address())).await?], AuthKind::Auth)
        .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_auth_quote_check() -> eyre::Result<()> {
    let key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    let mut env = Environment::setup_with_upgraded().await?;

    let response = env
        .relay_endpoint
        .prepare_upgrade_account(PrepareUpgradeAccountParameters {
            address: env.eoa.address(),
            chain_id: env.chain_id,
            capabilities: UpgradeAccountCapabilities {
                authorize_keys: vec![key.to_authorized(Some(env.eoa.address())).await?],
                delegation: env.delegation,
                fee_payer: None,
                fee_token: env.fee_token,
            },
        })
        .await?;

    // Sign UserOp digest
    let signature = env.eoa.root_signer().sign_hash(&response.digest).await?;
    let nonce = env.provider.get_transaction_count(env.eoa.address()).await?;

    // Change delegation that we are signing so it's a mismatch.
    env.delegation = Address::random();
    let authorization = AuthKind::Auth.sign(&env, nonce).await?;

    // Upgrade account.
    let response = env
        .relay_endpoint
        .upgrade_account(UpgradeAccountParameters {
            context: response.context,
            signature,
            authorization: authorization.clone(),
        })
        .await;

    assert!(response.is_err());

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn returning_customer() -> eyre::Result<()> {
    let env = Environment::setup_with_upgraded().await?;
    let key1 = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    let key2 = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();

    // Upgrade first time.
    upgrade_account(&env, &[key1.to_authorized(Some(env.eoa.address())).await?], AuthKind::Auth)
        .await?;

    // Clear 7702
    env.provider.anvil_set_code(env.eoa.address(), Bytes::new()).await?;

    // Upgrading again should succeed
    upgrade_account(&env, &[key2.to_authorized(Some(env.eoa.address())).await?], AuthKind::Auth)
        .await?;

    Ok(())
}
