//! Account upgrade related end-to-end test cases

use crate::e2e::{AuthKind, ExpectedOutcome, TxContext, environment::Environment};
use alloy::{
    eips::eip7702::SignedAuthorization,
    primitives::Bytes,
    providers::{Provider, ext::AnvilApi},
};
use relay::{
    rpc::RelayApiClient,
    types::{
        KeyType, KeyWith712Signer, SignedCalls,
        rpc::{
            AuthorizeKey, GetAuthorizationParameters, PrepareUpgradeAccountParameters,
            UpgradeAccountCapabilities, UpgradeAccountParameters, UpgradeAccountSignatures,
        },
    },
};

/// Will only execute the upgrade account flow without comitting to chain.
pub async fn upgrade_account_lazily(
    env: &Environment,
    authorize_keys: &[AuthorizeKey],
    auth: AuthKind,
) -> eyre::Result<SignedAuthorization> {
    let response = env
        .relay_endpoint
        .prepare_upgrade_account(PrepareUpgradeAccountParameters {
            address: env.eoa.address(),
            delegation: env.delegation,
            chain_id: None,
            capabilities: UpgradeAccountCapabilities { authorize_keys: authorize_keys.to_vec() },
        })
        .await?;

    // ensure its a multichain precall
    assert!(response.context.pre_call.is_multichain());

    // Sign Intent digest
    let precall_signature = env.eoa.sign_hash(&response.digests.exec).await?;

    // Sign 7702 delegation
    let nonce = env.provider().get_transaction_count(env.eoa.address()).await?;
    let authorization = auth.sign(env, nonce).await?;

    // Upgrade account.
    env.relay_endpoint
        .upgrade_account(UpgradeAccountParameters {
            context: response.context,
            signatures: UpgradeAccountSignatures {
                auth: authorization.signature()?,
                exec: precall_signature,
            },
        })
        .await?;

    Ok(authorization)
}

/// Will execute an empty prepareCalls & sendPreparedCalls after the upgrade account flow.
pub async fn upgrade_account_eagerly(
    env: &Environment,
    authorize_keys: &[AuthorizeKey],
    admin_key_signer: &KeyWith712Signer,
    auth: AuthKind,
) -> eyre::Result<SignedAuthorization> {
    let authorization = upgrade_account_lazily(env, authorize_keys, auth).await?;

    TxContext {
        expected: ExpectedOutcome::Pass,
        calls: vec![],
        key: Some(admin_key_signer),
        ..Default::default()
    }
    .process(0, env)
    .await?;

    Ok(authorization)
}

#[tokio::test(flavor = "multi_thread")]
async fn basic_upgrade() -> eyre::Result<()> {
    let env = Environment::setup().await?;
    let key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();

    upgrade_account_eagerly(&env, &[key.to_authorized()], &key, AuthKind::Auth).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn returning_customer() -> eyre::Result<()> {
    let env = Environment::setup().await?;
    let key1 = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    let key2 = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();

    // Upgrade first time.
    upgrade_account_eagerly(&env, &[key1.to_authorized()], &key1, AuthKind::Auth).await?;

    // Clear 7702
    env.provider().anvil_set_code(env.eoa.address(), Bytes::new()).await?;

    // Upgrading again should succeed
    upgrade_account_eagerly(&env, &[key2.to_authorized()], &key2, AuthKind::Auth).await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn get_authorization() -> eyre::Result<()> {
    let env = Environment::setup().await?;
    let key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();

    // First, prepare and upgrade the account
    let prepare_response = env
        .relay_endpoint
        .prepare_upgrade_account(PrepareUpgradeAccountParameters {
            address: env.eoa.address(),
            delegation: env.delegation,
            chain_id: None,
            capabilities: UpgradeAccountCapabilities { authorize_keys: vec![key.to_authorized()] },
        })
        .await?;

    // Sign Intent digest
    let precall_signature = env.eoa.sign_hash(&prepare_response.digests.exec).await?;

    // Sign 7702 delegation
    let nonce = env.provider().get_transaction_count(env.eoa.address()).await?;
    let authorization = AuthKind::Auth.sign(&env, nonce).await?;

    // Store the expected values before calling upgrade_account
    let authorization = authorization.clone();
    let init_data = prepare_response.context.pre_call.executionData.clone();

    // Upgrade account
    env.relay_endpoint
        .upgrade_account(UpgradeAccountParameters {
            context: prepare_response.context,
            signatures: UpgradeAccountSignatures {
                auth: authorization.signature()?,
                exec: precall_signature,
            },
        })
        .await?;

    let response = env
        .relay_endpoint
        .get_authorization(GetAuthorizationParameters { address: env.eoa.address() })
        .await?;

    assert_eq!(response.authorization, authorization);
    assert_eq!(response.data, init_data);

    Ok(())
}
