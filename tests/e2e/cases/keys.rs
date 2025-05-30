use crate::e2e::{
    AuthKind, ExpectedOutcome, MockErc20, TxContext, cases::upgrade_account_eagerly,
    environment::Environment, run_e2e,
};
use alloy::{primitives::U256, sol_types::SolCall};
use relay::{
    rpc::RelayApiClient,
    types::{
        CallPermission, KeyType, KeyWith712Signer,
        PortoAccount::SpendPeriod,
        rpc::{
            AuthorizeKey, AuthorizeKeyResponse, Meta, Permission, PrepareCallsCapabilities,
            PrepareCallsParameters, SpendPermission,
        },
    },
};

#[tokio::test(flavor = "multi_thread")]
async fn get_keys() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    // Set session key permissions
    let permissions = vec![
        Permission::Spend(SpendPermission {
            limit: U256::from(1000),
            period: SpendPeriod::Day,
            token: env.erc20,
        }),
        Permission::Call(CallPermission {
            to: env.erc20,
            selector: MockErc20::transferCall::SELECTOR.into(),
        }),
    ];

    let keys = [
        KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap(),
        KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap(),
        KeyWith712Signer::random_session(KeyType::P256)?
            .unwrap()
            .with_permissions(permissions.clone()),
    ];

    // Set expectable key responses from wallet_getKeys
    let expected_responses = keys
        .iter()
        .map(|key| {
            let permissions = if !key.isSuperAdmin { permissions.clone() } else { vec![] };
            AuthorizeKeyResponse {
                hash: key.key_hash(),
                authorize_key: AuthorizeKey { key: key.key().clone(), permissions },
            }
        })
        .collect::<Vec<_>>();

    // Upgrade account and check the first key has been added.
    {
        upgrade_account_eagerly(&env, &[keys[0].to_authorized()], &keys[0], AuthKind::Auth).await?;
        assert_eq!(env.get_eoa_authorized_keys().await?, expected_responses[..1]);
    }

    // Add the rest of the keys one by one.
    for (i, key) in [&keys[1], &keys[2]].into_iter().enumerate() {
        TxContext {
            authorization_keys: vec![key],
            expected: ExpectedOutcome::Pass,
            key: Some(&keys[0]),
            ..Default::default()
        }
        .process(i + 1, &env)
        .await?;

        assert_eq!(env.get_eoa_authorized_keys().await?, expected_responses[..(i + 2)]);
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_key() -> eyre::Result<()> {
    let key1 = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    let key2 = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();
    let key3 = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();

    run_e2e(|_env| {
        vec![
            TxContext {
                authorization_keys: vec![&key1],
                expected: ExpectedOutcome::Pass,
                ..Default::default()
            },
            TxContext {
                authorization_keys: vec![&key2],
                expected: ExpectedOutcome::Pass,
                key: Some(&key1),
                ..Default::default()
            },
            TxContext {
                authorization_keys: vec![&key3],
                revoke_keys: vec![&key1],
                expected: ExpectedOutcome::Pass,
                key: Some(&key2),
                ..Default::default()
            },
            TxContext {
                revoke_keys: vec![&key2, &key3],
                expected: ExpectedOutcome::FailEstimate,
                key: Some(&key1),
                ..Default::default()
            },
        ]
    })
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_backup_key() -> eyre::Result<()> {
    let key1 = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    let key2 = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();
    let key3 = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();

    run_e2e(|_env| {
        vec![
            TxContext {
                authorization_keys: vec![&key1],
                expected: ExpectedOutcome::Pass,
                ..Default::default()
            },
            TxContext {
                authorization_keys: vec![&key2],
                expected: ExpectedOutcome::Pass,
                key: Some(&key1),
                ..Default::default()
            },
            TxContext {
                revoke_keys: vec![&key2],
                expected: ExpectedOutcome::Pass,
                key: Some(&key2),
                ..Default::default()
            },
            TxContext {
                authorization_keys: vec![&key3],
                expected: ExpectedOutcome::Pass,
                key: Some(&key1),
                ..Default::default()
            },
            TxContext {
                revoke_keys: vec![&key1],
                expected: ExpectedOutcome::FailEstimate,
                key: Some(&key2),
                ..Default::default()
            },
        ]
    })
    .await?;
    Ok(())
}

/// Ensures that the simulation is successful if we pass a `prehash: true`. Even if we don't
/// actually prehash on `estimate_fee`,
#[tokio::test(flavor = "multi_thread")]
async fn ensure_prehash_simulation() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    // Prepare account
    let admin_key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    upgrade_account_eagerly(&env, &[admin_key.to_authorized()], &admin_key, AuthKind::Auth).await?;

    let mut call_key = admin_key.to_call_key();
    call_key.prehash = true;

    env.relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            from: Some(env.eoa.address()),
            calls: vec![],
            chain_id: env.chain_id,
            capabilities: PrepareCallsCapabilities {
                authorize_keys: vec![],
                revoke_keys: vec![],
                meta: Meta { fee_payer: None, fee_token: env.fee_token, nonce: None },
                pre_calls: vec![],
                pre_call: false,
            },
            key: Some(call_key),
        })
        .await?;

    Ok(())
}
