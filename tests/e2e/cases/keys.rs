use crate::e2e::{
    AuthKind, ExpectedOutcome, MockErc20, TxContext, config::AccountConfig, process_tx,
    run_e2e_prep,
};
use alloy::{primitives::U256, sol_types::SolCall};
use relay::types::{
    CallPermission,
    Delegation::SpendPeriod,
    KeyType, KeyWith712Signer,
    rpc::{AuthorizeKey, AuthorizeKeyResponse, Permission, SpendPermission},
};

#[tokio::test(flavor = "multi_thread")]
async fn get_keys() -> eyre::Result<()> {
    let upgraded_account = AccountConfig::Upgraded;
    let mut env = upgraded_account.setup_environment().await?;

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
                authorize_key: AuthorizeKey {
                    key: key.key().clone(),
                    permissions,
                    signature: None,
                },
            }
        })
        .collect::<Vec<_>>();

    // Upgrade account and check the first key has been added.
    {
        let mut tx = TxContext {
            authorization_keys: vec![&keys[0]],
            expected: ExpectedOutcome::Pass,
            auth: Some(AuthKind::Auth),
            ..Default::default()
        };
        upgraded_account.handle_first_tx(&mut env, 0, &mut tx).await?;

        assert_eq!(env.get_eoa_authorized_keys().await?, expected_responses[..1]);
    }

    // Add the rest of the keys one by one.
    for (i, key) in [&keys[1], &keys[2]].into_iter().enumerate() {
        let tx = TxContext {
            authorization_keys: vec![key],
            expected: ExpectedOutcome::Pass,
            key: Some(&keys[0]),
            ..Default::default()
        };

        process_tx(i + 1, tx, &env).await?;

        assert_eq!(env.get_eoa_authorized_keys().await?, expected_responses[..(i + 2)]);
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_key() -> eyre::Result<()> {
    let key1 = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    let key2 = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();
    let key3 = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();

    run_e2e_prep(|_env| {
        vec![
            TxContext {
                authorization_keys: vec![&key1],
                expected: ExpectedOutcome::Pass,
                auth: Some(AuthKind::Auth),
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

    run_e2e_prep(|_env| {
        vec![
            TxContext {
                authorization_keys: vec![&key1],
                expected: ExpectedOutcome::Pass,
                auth: Some(AuthKind::Auth),
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
