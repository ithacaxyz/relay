use crate::e2e::{
    AuthKind, ExpectedOutcome, MockErc20, TxContext, await_calls_status,
    cases::upgrade_account_eagerly, environment::Environment, run_e2e,
};
use alloy::{
    primitives::{U64, U256},
    sol_types::SolCall,
};
use relay::{
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    types::{
        CallPermission,
        IthacaAccount::SpendPeriod,
        KeyType, KeyWith712Signer,
        rpc::{
            AuthorizeKey, AuthorizeKeyResponse, Meta, Permission, PrepareCallsCapabilities,
            PrepareCallsParameters, SendPreparedCallsParameters, SpendPermission,
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
                meta: Meta { fee_payer: None, fee_token: Some(env.fee_token), nonce: None },
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
async fn get_keys_multichain() -> eyre::Result<()> {
    // Use true multi-chain environment
    let env = Environment::setup_multi_chain(2).await?;

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
    // Storage fallback should return keys for non-delegated chains
    if chain_ids.len() > 1 {
        let multi_chain_result = env
            .relay_endpoint
            .get_keys(relay::types::rpc::GetKeysParameters {
                address: env.eoa.address(),
                chain_ids: vec![chain_ids[0], chain_ids[1]], // Delegated + not-yet-committed
            })
            .await?;

        assert_eq!(multi_chain_result.len(), 2);
        // Delegated chain has admin + session
        assert_eq!(multi_chain_result.get(&U64::from(chain_ids[0])).unwrap().len(), 2);
        // Other chain falls back to storage (admin key only)
        assert_eq!(multi_chain_result.get(&U64::from(chain_ids[1])).unwrap().len(), 1);
    }

    // Test 3: Get keys for all chains (empty chain_ids)
    let all_chains_response = env
        .relay_endpoint
        .get_keys(relay::types::rpc::GetKeysParameters {
            address: env.eoa.address(),
            chain_ids: vec![],
        })
        .await?;

    // Should include all chains; delegated chain has 2 keys, others fall back to storage
    assert!(!all_chains_response.is_empty());
    assert!(all_chains_response.contains_key(&first_chain_id));
    assert_eq!(all_chains_response.get(&first_chain_id).unwrap().len(), 2); // admin + session key
    if chain_ids.len() > 1 {
        let second_chain_id = U64::from(chain_ids[1]);
        assert!(all_chains_response.contains_key(&second_chain_id));
        assert_eq!(all_chains_response.get(&second_chain_id).unwrap().len(), 1); // admin only via storage
    }

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
async fn get_keys_multichain_non_delegated_account() -> eyre::Result<()> {
    let env = Environment::setup_multi_chain(2).await?;

    // Try to get keys for a non-delegated account on specific chains
    let result = env
        .relay_endpoint
        .get_keys(relay::types::rpc::GetKeysParameters {
            address: env.eoa.address(),
            chain_ids: vec![env.chain_ids[0]],
        })
        .await;

    assert!(result.is_err(), "Expected error for non-delegated account");

    // Also fails when requesting multiple chains with zero delegated
    let result_multi = env
        .relay_endpoint
        .get_keys(relay::types::rpc::GetKeysParameters {
            address: env.eoa.address(),
            chain_ids: vec![env.chain_ids[0], env.chain_ids[1]],
        })
        .await;
    assert!(result_multi.is_err(), "Expected error when no chains are delegated");

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

    // Should include all chains; delegated chain has 1 key, other chains fall back to storage
    assert!(all_chains_result.contains_key(&U64::from(env.chain_ids[0])));
    assert_eq!(all_chains_result.get(&U64::from(env.chain_ids[0])).unwrap().len(), 1);
    assert!(all_chains_result.contains_key(&U64::from(env.chain_ids[1])));
    assert_eq!(all_chains_result.get(&U64::from(env.chain_ids[1])).unwrap().len(), 1);

    // Test with a specific chain: only delegated chain requested
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

    // Requesting the other chain explicitly now returns storage fallback
    let other_chain_result = env
        .relay_endpoint
        .get_keys(relay::types::rpc::GetKeysParameters {
            address: env.eoa.address(),
            chain_ids: vec![env.chain_ids[1]],
        })
        .await?;
    assert!(other_chain_result.contains_key(&U64::from(env.chain_ids[1])));
    assert_eq!(other_chain_result.get(&U64::from(env.chain_ids[1])).unwrap().len(), 1);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn get_keys_multichain_three_chains_two_have_session() -> eyre::Result<()> {
    // 3 chains; we will add a session key on only 2
    let env = Environment::setup_multi_chain(3).await?;

    let admin_key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();
    let session_key =
        KeyWith712Signer::random_session(KeyType::P256)?.unwrap().with_permissions(vec![
            Permission::Call(CallPermission {
                to: env.erc20,
                selector: MockErc20::transferCall::SELECTOR.into(),
            }),
        ]);

    // Upgrade account (authorizes admin key) and commit on chain 0
    upgrade_account_eagerly(&env, &[admin_key.to_authorized()], &admin_key, AuthKind::Auth).await?;

    // Add session key on chain 0 and chain 1 by calling prepare+send explicitly
    for &chain_index in &[0usize, 1usize] {
        let resp = env
            .relay_endpoint
            .prepare_calls(PrepareCallsParameters {
                from: Some(env.eoa.address()),
                calls: vec![],
                chain_id: env.chain_id_for(chain_index),
                capabilities: PrepareCallsCapabilities {
                    authorize_keys: vec![session_key.to_authorized()],
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

        let sig = admin_key.sign_payload_hash(resp.digest).await?;
        let bundle = env
            .relay_endpoint
            .send_prepared_calls(SendPreparedCallsParameters {
                capabilities: Default::default(),
                context: resp.context,
                key: Some(admin_key.to_call_key()),
                signature: sig,
            })
            .await?;

        // Wait for the bundle to finalize to ensure keys are committed on-chain
        let _ = await_calls_status(&env, bundle.id).await?;
    }

    // Now query keys across all 3 chains
    let response = env
        .relay_endpoint
        .get_keys(relay::types::rpc::GetKeysParameters {
            address: env.eoa.address(),
            chain_ids: vec![env.chain_ids[0], env.chain_ids[1], env.chain_ids[2]],
        })
        .await?;

    // Chains 0 and 1 should have admin + session (2 keys)
    assert_eq!(response.get(&U64::from(env.chain_ids[0])).unwrap().len(), 2);
    assert_eq!(response.get(&U64::from(env.chain_ids[1])).unwrap().len(), 2);

    // Chain 2 should only have admin (fallback from storage), no session key
    assert_eq!(response.get(&U64::from(env.chain_ids[2])).unwrap().len(), 1);

    Ok(())
}
