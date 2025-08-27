use crate::e2e::{
    AuthKind, ExpectedOutcome, MockErc20, TxContext, cases::upgrade_account_eagerly,
    environment::Environment, run_e2e,
};
use alloy::{
    primitives::{U64, U256},
    sol_types::SolCall,
};
use relay::{
    rpc::RelayApiClient,
    types::{
        CallPermission,
        IthacaAccount::SpendPeriod,
        KeyType, KeyWith712Signer,
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
            key: Some(call_key),
        })
        .await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn get_keys_multi_chain() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    let admin_key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();
    let session_key =
        KeyWith712Signer::random_session(KeyType::P256)?.unwrap().with_permissions(vec![
            Permission::Call(CallPermission {
                to: env.erc20,
                selector: MockErc20::transferCall::SELECTOR.into(),
            }),
        ]);

    upgrade_account_eagerly(&env, &[admin_key.to_authorized()], &admin_key, AuthKind::Auth).await?;

    // Add session key
    TxContext {
        authorization_keys: vec![&session_key],
        expected: ExpectedOutcome::Pass,
        key: Some(&admin_key),
        ..Default::default()
    }
    .process(0, &env)
    .await?;

    let chain_id = env.chain_id();
    let chain_ids = env.chain_ids;

    // Test 1: Get keys for a single chain (where we delegated)
    let response = env
        .relay_endpoint
        .get_keys(relay::types::rpc::GetKeysParameters {
            address: env.eoa.address(),
            chain_ids: vec![chain_id],
        })
        .await?;

    let first_chain_id = U64::from(chain_id);
    assert!(response.contains_key(&first_chain_id));
    assert_eq!(response.get(&first_chain_id).unwrap().len(), 2); // admin + session key

    // Test 2: Request multiple chains when only delegated on one
    if chain_ids.len() > 1 {
        let multi_chain_result = env
            .relay_endpoint
            .get_keys(relay::types::rpc::GetKeysParameters {
                address: env.eoa.address(),
                chain_ids: vec![chain_ids[0], chain_ids[1]], // Delegated + non-delegated
            })
            .await?;

        // Should only have keys for the chain where we delegated
        assert_eq!(multi_chain_result.len(), 1);
        assert!(multi_chain_result.contains_key(&first_chain_id));

        let non_delegated_chain = U64::from(chain_ids[1]);
        assert!(!multi_chain_result.contains_key(&non_delegated_chain));
    }

    // Test 3: Get keys for all chains (empty chain_ids)
    let all_chains_response = env
        .relay_endpoint
        .get_keys(relay::types::rpc::GetKeysParameters {
            address: env.eoa.address(),
            chain_ids: vec![],
        })
        .await?;

    // Should only include the chain where we delegated
    assert!(!all_chains_response.is_empty());
    assert!(all_chains_response.contains_key(&first_chain_id));
    assert_eq!(all_chains_response.get(&first_chain_id).unwrap().len(), 2); // admin + session key

    // Test 4: Request an unsupported chain ID
    let non_existent_chain = 999999u64;
    let unsupported_result = env
        .relay_endpoint
        .get_keys(relay::types::rpc::GetKeysParameters {
            address: env.eoa.address(),
            chain_ids: vec![non_existent_chain],
        })
        .await;

    // Should fail because chain is not supported by the relay
    assert!(unsupported_result.is_err(), "Expected error for unsupported chain");

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn get_keys_non_delegated_account() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    // Try to get keys for a non-delegated account on specific chains
    let result = env
        .relay_endpoint
        .get_keys(relay::types::rpc::GetKeysParameters {
            address: env.eoa.address(),
            chain_ids: vec![env.chain_ids[0]],
        })
        .await;

    assert!(result.is_err(), "Expected error for non-delegated account");

    // Delegate on 1 chain
    let admin_key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();
    upgrade_account_eagerly(&env, &[admin_key.to_authorized()], &admin_key, AuthKind::Auth).await?;

    // Test with all chains (empty chain_ids)
    let all_chains_result = env
        .relay_endpoint
        .get_keys(relay::types::rpc::GetKeysParameters {
            address: env.eoa.address(),
            chain_ids: vec![],
        })
        .await?;

    // Should return keys for the delegated chain
    assert!(all_chains_result.contains_key(&U64::from(env.chain_ids[0])));
    assert_eq!(all_chains_result.get(&U64::from(env.chain_ids[0])).unwrap().len(), 1);

    // Test with multiple chains, 1 delegated
    let multi_chain_result = env
        .relay_endpoint
        .get_keys(relay::types::rpc::GetKeysParameters {
            address: env.eoa.address(),
            chain_ids: vec![env.chain_ids[0]],
        })
        .await?;

    // Should return keys for the delegated chain
    assert!(multi_chain_result.contains_key(&U64::from(env.chain_ids[0])));
    assert_eq!(multi_chain_result.get(&U64::from(env.chain_ids[0])).unwrap().len(), 1);

    // TODO: Test with multiple chains, 0 delegated (once we have multiple chains in the test env)

    Ok(())
}
