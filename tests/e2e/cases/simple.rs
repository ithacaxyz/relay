//! Relay simple end-to-end test cases

use crate::{
    check,
    e2e::{cases::prep_account, common_calls as calls, *},
};
use alloy::{primitives::U256, sol_types::SolValue, uint};
use eyre::Result;
use relay::{
    signers::DynSigner,
    types::{
        Delegation::SpendPeriod,
        IERC20, KeyType, KeyWith712Signer, Signature,
        rpc::{Permission, SpendPermission},
    },
};

#[tokio::test(flavor = "multi_thread")]
async fn auth_then_erc20_transfer() -> Result<()> {
    for key_type in [KeyType::WebAuthnP256] {
        let key = KeyWith712Signer::random_admin(key_type)?.unwrap();

        // The first TX will bundle the prep/upgrade calls
        run_e2e_prep_erc20(|env| {
            let to = Address::random();
            let transfer_amount = U256::from(10);
            vec![
                TxContext {
                    authorization_keys: vec![&key],
                    expected: ExpectedOutcome::Pass,
                    auth: Some(AuthKind::Auth),
                    ..Default::default()
                },
                TxContext {
                    calls: vec![calls::transfer(env.erc20, to, transfer_amount)],
                    expected: ExpectedOutcome::Pass,
                    key: Some(&key),
                    post_tx: check!(|env, _tx| {
                        assert_eq!(
                            transfer_amount,
                            IERC20::IERC20Instance::new(env.erc20, &env.provider)
                                .balanceOf(to)
                                .call()
                                .await?
                        );
                        Ok(())
                    }),
                    ..Default::default()
                },
            ]
        })
        .await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_auth_nonce() -> Result<()> {
    let key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    run_e2e_upgraded(|_env| {
        vec![TxContext {
            authorization_keys: vec![&key],
            expected: ExpectedOutcome::FailSend,
            auth: Some(AuthKind::modified_nonce(123)),
            ..Default::default()
        }]
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_auth_signature() -> Result<()> {
    let key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    let dummy_signer = DynSigner::from_signing_key(
        "0x42424242428f97a5a0044266f0945389dc9e86dae88c7a8412f4603b6b78690d",
    )
    .await?;

    run_e2e_upgraded(|_env| {
        vec![TxContext {
            authorization_keys: vec![&key],
            expected: ExpectedOutcome::FailSend,
            // Signing with an unrelated key should fail during sendAction when calling eth_call
            auth: Some(AuthKind::modified_signer(dummy_signer.clone())),
            ..Default::default()
        }]
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_then_two_authorizes_then_erc20_transfer() -> Result<()> {
    let key1 = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    let key2 = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();

    run_e2e(|env| {
        vec![
            TxContext {
                expected: ExpectedOutcome::Pass,
                auth: Some(AuthKind::Auth),
                authorization_keys: vec![&key1],
                ..Default::default()
            },
            TxContext {
                expected: ExpectedOutcome::Pass,
                authorization_keys: vec![&key2],
                key: Some(&key1),
                ..Default::default()
            },
            TxContext {
                expected: ExpectedOutcome::Pass,
                calls: vec![calls::transfer(env.erc20, Address::ZERO, U256::from(10))],
                key: Some(&key2),
                ..Default::default()
            },
        ]
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn spend_limits() -> Result<()> {
    let key1 = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    let session_key = KeyWith712Signer::random_session(KeyType::P256)?.unwrap();

    run_e2e(|env| {
        vec![
            // delegate, auth and set spend limit
            TxContext {
                expected: ExpectedOutcome::Pass,
                authorization_keys: vec![&key1],
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            // successful transfer
            TxContext {
                expected: ExpectedOutcome::Pass,
                authorization_keys: vec![&session_key],
                calls: vec![
                    calls::daily_limit(env.fee_token, U256::from(1e18), session_key.key()),
                    calls::can_execute_all(env.erc20, session_key.key_hash()),
                    calls::daily_limit(env.erc20, U256::from(15), session_key.key()),
                ],
                key: Some(&key1),
                ..Default::default()
            },
            // overspend transfer should fail
            TxContext {
                expected: ExpectedOutcome::FailEstimate,
                calls: vec![calls::transfer(env.erc20, Address::ZERO, U256::from(100))],
                key: Some(&session_key),
                ..Default::default()
            },
        ]
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn native_transfer() -> Result<()> {
    for key_type in [KeyType::Secp256k1, KeyType::WebAuthnP256] {
        let key = KeyWith712Signer::random_admin(key_type)?.unwrap();

        run_e2e(|_env| {
            vec![
                TxContext {
                    authorization_keys: vec![&key],
                    expected: ExpectedOutcome::Pass,
                    auth: Some(AuthKind::Auth),
                    ..Default::default()
                },
                TxContext {
                    calls: vec![calls::transfer_native(Address::ZERO, U256::from(10))],
                    expected: ExpectedOutcome::Pass,
                    key: Some(&key),
                    ..Default::default()
                },
            ]
        })
        .await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn spend_limits_bundled() -> Result<()> {
    let key1 = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();
    let session_key = KeyWith712Signer::random_session(KeyType::P256)?.unwrap();

    run_e2e_prep_erc20(|env| {
        vec![
            TxContext {
                expected: ExpectedOutcome::Pass,
                authorization_keys: vec![&key1],
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            // authorize session key
            TxContext {
                expected: ExpectedOutcome::Pass,
                authorization_keys: vec![&session_key],
                calls: vec![
                    calls::daily_limit(env.fee_token, U256::from(1e18), session_key.key()),
                    calls::daily_limit(env.erc20, U256::from(15), session_key.key()),
                    calls::can_execute_all(env.erc20, session_key.key_hash()),
                ],
                key: Some(&key1),
                ..Default::default()
            },
            // successful transfer that should decrease the daily allowance
            TxContext {
                expected: ExpectedOutcome::Pass,
                calls: vec![calls::transfer(env.erc20, Address::ZERO, U256::from(10))],
                key: Some(&session_key),
                ..Default::default()
            },
            // overspend transfer should fail
            TxContext {
                expected: ExpectedOutcome::FailEstimate,
                calls: vec![calls::transfer(env.erc20, Address::ZERO, U256::from(10))],
                key: Some(&session_key),
                ..Default::default()
            },
        ]
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn spend_limits_bundle_failure() -> Result<()> {
    let key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    let session_key = KeyWith712Signer::random_session(KeyType::P256)?.unwrap();
    run_e2e_prep(|env| {
        vec![TxContext {
            authorization_keys: vec![&key],
            expected: ExpectedOutcome::FailEstimate,
            // Bundle session key authorization as a pre-op
            pre_ops: vec![TxContext {
                authorization_keys: vec![&session_key],
                calls: vec![
                    calls::can_execute_all(env.erc20, session_key.key_hash()),
                    calls::daily_limit(env.erc20, U256::from(15), session_key.key()),
                ],
                expected: ExpectedOutcome::Pass,
                key: Some(&key),
                // use random nonce sequence
                nonce: Some(U256::from_be_bytes(*B256::random()) << 64),
                ..Default::default()
            }],
            // Bundled overspend should fail
            calls: vec![calls::transfer(env.erc20, Address::ZERO, U256::from(20))],
            // The userop is signed by the session key itself
            key: Some(&session_key),
            ..Default::default()
        }]
    })
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn no_fee_tx() -> Result<()> {
    let key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();

    // User with no balance on the fee token should fail on prepareCalls.
    run_e2e_prep_erc20(|env| {
        let to = Address::random();
        let transfer_amount = U256::from(10);

        vec![TxContext {
            authorization_keys: vec![&key],
            expected: ExpectedOutcome::FailEstimate, // no balance on fee token
            fee_token: Some(env.erc20s[2]),          // has not been minted
            calls: vec![calls::transfer(env.erc20, to, transfer_amount)],
            ..Default::default()
        }]
    })
    .await
}

/// Ensures prepareCalls can handle two successive requests with an empty nonce.
#[tokio::test(flavor = "multi_thread")]
async fn empty_request_nonce() -> eyre::Result<()> {
    let mut env = Environment::setup_with_prep().await?;
    let admin_key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();

    prep_account(&mut env, &[&admin_key]).await?;

    TxContext {
        expected: ExpectedOutcome::Pass,
        calls: vec![common_calls::transfer(env.erc20, env.erc20, U256::from(10))],
        key: Some(&admin_key),
        ..Default::default()
    }
    .process(0, &env)
    .await?;

    // preop
    let response = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            from: Some(env.eoa.address()),
            calls: vec![],
            chain_id: env.chain_id,
            capabilities: PrepareCallsCapabilities {
                authorize_keys: vec![],
                revoke_keys: vec![],
                meta: Meta { fee_payer: None, fee_token: env.fee_token, nonce: None },
                pre_ops: vec![],
                pre_op: true,
            },
            key: Some(admin_key.to_call_key()),
        })
        .await?;

    let mut preop = response.context.take_preop().unwrap();
    preop.signature = Signature {
        innerSignature: admin_key.sign_payload_hash(response.digest).await?,
        keyHash: admin_key.key_hash(),
        prehash: false,
    }
    .abi_encode_packed()
    .into();

    let response = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            from: Some(env.eoa.address()),
            calls: vec![],
            chain_id: env.chain_id,
            capabilities: PrepareCallsCapabilities {
                authorize_keys: vec![],
                revoke_keys: vec![],
                meta: Meta { fee_payer: None, fee_token: env.fee_token, nonce: None },
                pre_ops: vec![preop],
                pre_op: false,
            },
            key: Some(admin_key.to_call_key()),
        })
        .await?;

    assert!(response.context.take_quote().unwrap().ty().op.nonce == uint!(1_U256));

    Ok(())
}

/// Ensures sign up only requires one passkey popup.
#[tokio::test(flavor = "multi_thread")]
async fn single_sign_up_popup() -> eyre::Result<()> {
    let mut env = Environment::setup_with_prep().await?;

    let admin_key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();
    let session_key =
        KeyWith712Signer::random_session(KeyType::P256)?.unwrap().with_permissions(vec![
            Permission::Spend(SpendPermission {
                limit: U256::MAX,
                period: SpendPeriod::Day,
                token: env.fee_token,
            }),
        ]);

    // Call prepare_calls without a from authorizing session key with admin key.
    let response = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            from: None,
            calls: vec![],
            chain_id: env.chain_id,
            capabilities: PrepareCallsCapabilities {
                authorize_keys: vec![session_key.to_authorized(None).await?],
                revoke_keys: vec![],
                meta: Meta { fee_payer: None, fee_token: env.fee_token, nonce: None },
                pre_ops: vec![],
                pre_op: true,
            },
            key: None,
        })
        .await?;

    let mut accountless_preop = response.context.take_preop().unwrap();
    accountless_preop.signature = Signature {
        innerSignature: admin_key.sign_payload_hash(response.digest).await?,
        keyHash: admin_key.key_hash(),
        prehash: false,
    }
    .abi_encode_packed()
    .into();

    // prepareCreateAccount && createAccount
    prep_account(&mut env, &[&admin_key]).await?;

    // initPrep + accountless preop
    let response = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            from: Some(env.eoa.address()),
            calls: vec![],
            chain_id: env.chain_id,
            capabilities: PrepareCallsCapabilities {
                authorize_keys: vec![],
                revoke_keys: vec![],
                meta: Meta { fee_payer: None, fee_token: env.fee_token, nonce: None },
                pre_ops: vec![accountless_preop],
                pre_op: false,
            },
            key: Some(session_key.to_call_key()),
        })
        .await?;

    let bundle_id = send_prepared_calls(
        &env,
        &session_key,
        session_key.sign_payload_hash(response.digest).await?,
        response.context,
    )
    .await?;

    // Wait for bundle to not be pending.
    let status = await_calls_status(&env, bundle_id).await?;
    assert!(status.status.is_confirmed());

    Ok(())
}
