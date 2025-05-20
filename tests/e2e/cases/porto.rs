//! Porto equivalent end-to-end test cases

use crate::e2e::{common_calls as calls, *};
use alloy::{primitives::U256, sol_types::SolCall};
use eyre::Result;
use relay::types::{Call, KeyType, KeyWith712Signer};

/// porto test: "behavior: delegation"
#[tokio::test(flavor = "multi_thread")]
async fn behavior_delegation() -> Result<()> {
    let key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    run_e2e(|env| {
        vec![
            // Authorize key (delegation provided in the call)
            TxContext {
                authorization_keys: vec![&key],
                expected: ExpectedOutcome::Pass,
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            // Perform a transfer signed by the authorized key
            TxContext {
                calls: vec![calls::transfer(env.erc20, Address::ZERO, U256::from(10000000u64))],
                expected: ExpectedOutcome::Pass,
                key: Some(&key),
                ..Default::default()
            },
        ]
    })
    .await?;
    Ok(())
}

/// porto test: "behavior: spend limit + execution guard"
#[tokio::test(flavor = "multi_thread")]
async fn execution_guard_spend_limit_and_guard() -> Result<()> {
    let key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    let session_key = KeyWith712Signer::random_session(KeyType::P256)?.unwrap();
    run_e2e(|env| {
        vec![
            // Authorize admin key
            TxContext {
                authorization_keys: vec![&key],
                expected: ExpectedOutcome::Pass,
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            // Authorize another key, set execution guard and spend limit (1.5 ETH) for it
            TxContext {
                authorization_keys: vec![&session_key],
                calls: vec![
                    calls::daily_limit(env.fee_token, U256::from(1e18), session_key.key()),
                    Call {
                        to: Address::ZERO,
                        value: U256::ZERO,
                        data: PortoAccount::setCanExecuteCall {
                            keyHash: session_key.key_hash(),
                            can: true,
                            fnSel: DEFAULT_EXECUTE_SELECTOR,
                            target: DEFAULT_EXECUTE_TO,
                        }
                        .abi_encode()
                        .into(),
                    },
                    calls::daily_limit(env.erc20, U256::from(150u64), &session_key),
                ],
                key: Some(&key),
                expected: ExpectedOutcome::Pass,
                ..Default::default()
            },
            // Successful transfer
            TxContext {
                calls: vec![calls::transfer(env.erc20, Address::ZERO, U256::from(100u64))],
                expected: ExpectedOutcome::Pass,
                key: Some(&session_key),
                ..Default::default()
            },
            // Another transfer exceeds spend limit → fail
            TxContext {
                calls: vec![calls::transfer(env.erc20, Address::ZERO, U256::from(100u64))],
                expected: ExpectedOutcome::FailEstimate,
                key: Some(&session_key),
                ..Default::default()
            },
        ]
    })
    .await?;
    Ok(())
}

/// porto test: "behavior: target scope"
#[tokio::test(flavor = "multi_thread")]
async fn execution_guard_target_scope() -> Result<()> {
    let key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    let session_key = KeyWith712Signer::random_session(KeyType::P256)?.unwrap();

    run_e2e(|env| {
        vec![
            // Authorize admin key
            TxContext {
                authorization_keys: vec![&key],
                expected: ExpectedOutcome::Pass,
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            // Authorize another key and set execution guard with a target scope (only env.erc20
            // allowed)
            TxContext {
                authorization_keys: vec![&session_key],
                calls: vec![
                    calls::daily_limit(env.erc20, U256::from(10000000u64), session_key.key()),
                    calls::daily_limit(env.fee_token, U256::from(1e18), session_key.key()),
                    Call {
                        to: Address::ZERO,
                        value: U256::ZERO,
                        data: PortoAccount::setCanExecuteCall {
                            keyHash: session_key.key_hash(),
                            fnSel: DEFAULT_EXECUTE_SELECTOR,
                            target: env.erc20,
                            can: true,
                        }
                        .abi_encode()
                        .into(),
                    },
                ],
                expected: ExpectedOutcome::Pass,
                key: Some(&key),
                ..Default::default()
            },
            // Valid transfer (target matches)
            TxContext {
                calls: vec![calls::transfer(env.erc20, Address::ZERO, U256::from(10000000u64))],
                expected: ExpectedOutcome::Pass,
                key: Some(&session_key),
                ..Default::default()
            },
            // Failing transfer (different target)
            TxContext {
                calls: vec![calls::transfer(env.erc20s[1], Address::ZERO, U256::from(10000000u64))],
                expected: ExpectedOutcome::FailEstimate,
                key: Some(&session_key),
                ..Default::default()
            },
        ]
    })
    .await?;
    Ok(())
}

/// porto test: "behavior: target scope + selector"
#[tokio::test(flavor = "multi_thread")]
async fn execution_guard_target_scope_selector() -> Result<()> {
    let key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    let session_key = KeyWith712Signer::random_session(KeyType::P256)?.unwrap();
    run_e2e(|env| {
        vec![
            // Authorize admin key
            TxContext {
                authorization_keys: vec![&key],
                expected: ExpectedOutcome::Pass,
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            // Authorize another key and set execution guard with target and selector (for
            // "transfer")
            TxContext {
                authorization_keys: vec![&session_key],
                calls: vec![
                    calls::daily_limit(env.fee_token, U256::from(1e18), session_key.key()),
                    calls::daily_limit(env.erc20, U256::from(10000000u64), session_key.key()),
                    Call {
                        to: Address::ZERO,
                        value: U256::ZERO,
                        data: PortoAccount::setCanExecuteCall {
                            keyHash: session_key.key_hash(),
                            can: true,
                            fnSel: MockErc20::transferCall::SELECTOR.into(),
                            target: env.erc20,
                        }
                        .abi_encode()
                        .into(),
                    },
                ],
                expected: ExpectedOutcome::Pass,
                key: Some(&key),
                ..Default::default()
            },
            // Valid transfer call using "transfer"
            TxContext {
                calls: vec![calls::transfer(env.erc20, Address::ZERO, U256::from(10000000u64))],
                expected: ExpectedOutcome::Pass,
                key: Some(&session_key),
                ..Default::default()
            },
            // Failing call using a different selector (e.g. "mint")
            TxContext {
                calls: vec![calls::mint(env.erc20, Address::ZERO, U256::from(10000000u64))],
                expected: ExpectedOutcome::FailEstimate,
                key: Some(&session_key),
                ..Default::default()
            },
        ]
    })
    .await?;
    Ok(())
}

/// porto test: "default"
#[tokio::test(flavor = "multi_thread")]
async fn send_default() -> Result<()> {
    let key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    run_e2e(|env| {
        vec![
            // Delegate (empty calls with auth)
            TxContext {
                authorization_keys: vec![&key],
                expected: ExpectedOutcome::Pass,
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            // Transfer call: transfer 0.0001 ETH worth (using a placeholder value)
            TxContext {
                calls: vec![calls::transfer(
                    env.erc20,
                    Address::ZERO,
                    U256::from(100000000000000u64),
                )],
                key: Some(&key),
                expected: ExpectedOutcome::Pass,
                ..Default::default()
            },
        ]
    })
    .await?;
    Ok(())
}

/// porto test: "default" (execution guard)
#[tokio::test(flavor = "multi_thread")]
async fn execution_guard_default() -> Result<()> {
    let key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    let session_key = KeyWith712Signer::random_session(KeyType::P256)?.unwrap();
    run_e2e(|env| {
        vec![
            // Authorize admin key with delegation
            TxContext {
                authorization_keys: vec![&key],
                expected: ExpectedOutcome::Pass,
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            // Authorize and set execution guard using default values for selector and target
            TxContext {
                authorization_keys: vec![&session_key],
                calls: vec![
                    calls::daily_limit(env.fee_token, U256::from(1e18), session_key.key()),
                    calls::daily_limit(env.erc20, U256::from(10000000u64), session_key.key()),
                    Call {
                        to: Address::ZERO,
                        value: U256::ZERO,
                        data: PortoAccount::setCanExecuteCall {
                            keyHash: session_key.key_hash(),
                            can: true,
                            fnSel: DEFAULT_EXECUTE_SELECTOR,
                            target: DEFAULT_EXECUTE_TO,
                        }
                        .abi_encode()
                        .into(),
                    },
                ],
                expected: ExpectedOutcome::Pass,
                key: Some(&key),
                ..Default::default()
            },
            // Transfer signed by the second key
            TxContext {
                calls: vec![calls::transfer(env.erc20, Address::ZERO, U256::from(10000000u64))],
                expected: ExpectedOutcome::Pass,
                key: Some(&session_key),
                ..Default::default()
            },
        ]
    })
    .await?;
    Ok(())
}

/// porto test: "default" (prepare & sendPrepared)
#[tokio::test(flavor = "multi_thread")]
async fn prepare_send_prepared_default() -> Result<()> {
    let key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    run_e2e(|env| {
        vec![
            // Delegate
            TxContext {
                expected: ExpectedOutcome::Pass,
                auth: Some(AuthKind::Auth),
                authorization_keys: vec![&key],
                ..Default::default()
            },
            // Prepared transfer call (simulating prepare then sendPrepared)
            TxContext {
                calls: vec![calls::transfer(env.erc20, Address::ZERO, U256::from(10000000u64))],
                expected: ExpectedOutcome::Pass,
                key: Some(&key),
                ..Default::default()
            },
        ]
    })
    .await?;
    Ok(())
}

/// porto test: "delegated: false, key: EOA, keyToAuthorize: P256"
#[tokio::test(flavor = "multi_thread")]
async fn delegated_false_eoa_key_to_authorize_p256() -> Result<()> {
    let key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    run_e2e(|env| {
        vec![
            // Send authorize call (EOA signs; delegation parameter provided)
            TxContext {
                authorization_keys: vec![&key],
                expected: ExpectedOutcome::Pass,
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            // Transfer call signed by the newly authorized key
            TxContext {
                calls: vec![calls::transfer(env.erc20, Address::ZERO, U256::from(10000000u64))],
                expected: ExpectedOutcome::Pass,
                key: Some(&key),
                ..Default::default()
            },
        ]
    })
    .await?;
    Ok(())
}

/// porto test: "delegated: true, key: EOA, keyToAuthorize: P256"
#[tokio::test(flavor = "multi_thread")]
async fn delegated_true_eoa_key_to_authorize_p256() -> Result<()> {
    let key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    run_e2e(|env| {
        vec![
            // Authorize the new key (signed by EOA)
            TxContext {
                authorization_keys: vec![&key],
                expected: ExpectedOutcome::Pass,
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            // Transfer call signed by the authorized key
            TxContext {
                calls: vec![calls::transfer(env.erc20, Address::ZERO, U256::from(10000000u64))],
                expected: ExpectedOutcome::Pass,
                key: Some(&key),
                ..Default::default()
            },
        ]
    })
    .await?;
    Ok(())
}

/// porto test: "key: P256, keyToAuthorize: P256"
#[tokio::test(flavor = "multi_thread")]
async fn key_p256_key_to_authorize_p256() -> Result<()> {
    let key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    let another_key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    run_e2e(|env| {
        vec![
            // Authorize first key
            TxContext {
                authorization_keys: vec![&key],
                expected: ExpectedOutcome::Pass,
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            // Authorize a second (P256) key using the first key
            TxContext {
                authorization_keys: vec![&another_key],
                expected: ExpectedOutcome::Pass,
                key: Some(&key),
                ..Default::default()
            },
            // Transfer using the second key
            TxContext {
                calls: vec![calls::transfer(env.erc20, Address::ZERO, U256::from(10000000u64))],
                expected: ExpectedOutcome::Pass,
                key: Some(&another_key),
                ..Default::default()
            },
        ]
    })
    .await?;
    Ok(())
}

/// porto test: "key: P256, keyToAuthorize: P256 (session)"
#[tokio::test(flavor = "multi_thread")]
async fn key_p256_key_to_authorize_p256_session() -> Result<()> {
    let key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    // Create a session key (using P256 again)
    let session_key = KeyWith712Signer::random_session(KeyType::P256)?.unwrap();
    run_e2e(|env| {
        vec![
            // Authorize the admin key (P256)
            TxContext {
                authorization_keys: vec![&key],
                expected: ExpectedOutcome::Pass,
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            // Authorize the session key and set its execution guard using
            // Delegation::setCanExecuteCall with defaults
            TxContext {
                authorization_keys: vec![&session_key],
                calls: vec![
                    calls::daily_limit(env.fee_token, U256::from(1e18), session_key.key()),
                    calls::daily_limit(env.erc20, U256::from(10000000u64), session_key.key()),
                    Call {
                        to: Address::ZERO,
                        value: U256::ZERO,
                        data: PortoAccount::setCanExecuteCall {
                            keyHash: session_key.key_hash(),
                            can: true,
                            fnSel: DEFAULT_EXECUTE_SELECTOR,
                            target: DEFAULT_EXECUTE_TO,
                        }
                        .abi_encode()
                        .into(),
                    },
                ],
                expected: ExpectedOutcome::Pass,
                key: Some(&key),
                ..Default::default()
            },
            // Transfer signed by the session key
            TxContext {
                calls: vec![calls::transfer(env.erc20, Address::ZERO, U256::from(10000000u64))],
                expected: ExpectedOutcome::Pass,
                key: Some(&session_key),
                ..Default::default()
            },
        ]
    })
    .await?;
    Ok(())
}

/// porto test: "key: P256, keyToAuthorize: WebCryptoP256"
#[tokio::test(flavor = "multi_thread")]
async fn key_p256_key_to_authorize_webcryptop256() -> Result<()> {
    let key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    let another_key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    run_e2e(|env| {
        vec![
            // Delegate
            TxContext {
                authorization_keys: vec![&key],
                expected: ExpectedOutcome::Pass,
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            // Authorize the second key (WebCryptoP256) using the first key
            TxContext {
                authorization_keys: vec![&another_key],
                expected: ExpectedOutcome::Pass,
                key: Some(&key),
                ..Default::default()
            },
            // Transfer signed by the second key
            TxContext {
                calls: vec![calls::transfer(env.erc20, Address::ZERO, U256::from(10000000u64))],
                expected: ExpectedOutcome::Pass,
                key: Some(&another_key),
                ..Default::default()
            },
        ]
    })
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn session_key_pre_op() -> Result<()> {
    let key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    let session_key = KeyWith712Signer::random_session(KeyType::P256)?.unwrap();
    run_e2e(|env| {
        assert!(env.erc20 != env.fee_token);
        vec![
            // Authorize the admin key
            TxContext {
                authorization_keys: vec![&key],
                expected: ExpectedOutcome::Pass,
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            TxContext {
                expected: ExpectedOutcome::Pass,
                // Bundle session key authorization as a pre-op
                pre_ops: vec![TxContext {
                    authorization_keys: vec![&session_key],
                    calls: vec![
                        calls::daily_limit(env.fee_token, U256::from(1e18), session_key.key()),
                        calls::can_execute_all(env.erc20, session_key.key_hash()),
                        calls::daily_limit(env.erc20, U256::from(10000000u64), session_key.key()),
                    ],
                    expected: ExpectedOutcome::Pass,
                    key: Some(&key),
                    // use random nonce sequence
                    nonce: Some(U256::from_be_bytes(*B256::random()) << 64),
                    ..Default::default()
                }],
                // Execute the transfer via session key in the same intent
                calls: vec![calls::transfer(env.erc20, Address::ZERO, U256::from(10000000u64))],
                // The intent is signed by the session key itself
                key: Some(&session_key),
                ..Default::default()
            },
        ]
    })
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn session_key_pre_op_prep_single_tx() -> Result<()> {
    let key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    let session_key = KeyWith712Signer::random_session(KeyType::P256)?.unwrap();
    run_e2e_prep(|env| {
        assert!(env.erc20 != env.fee_token);
        vec![TxContext {
            authorization_keys: vec![&key],
            expected: ExpectedOutcome::Pass,
            // Bundle session key authorization as a pre-op
            pre_ops: vec![TxContext {
                authorization_keys: vec![&session_key],
                calls: vec![
                    calls::daily_limit(env.fee_token, U256::from(1e18), session_key.key()),
                    calls::daily_limit(env.erc20, U256::from(10000000u64), session_key.key()),
                    calls::can_execute_all(env.erc20, session_key.key_hash()),
                ],
                expected: ExpectedOutcome::Pass,
                key: Some(&key),
                // use random nonce sequence
                nonce: Some(U256::from_be_bytes(*B256::random()) << 64),
                ..Default::default()
            }],
            // Execute the transfer via session key in the same intent
            calls: vec![calls::transfer(env.erc20, Address::ZERO, U256::from(10000000u64))],
            // The intent is signed by the session key itself
            key: Some(&session_key),
            ..Default::default()
        }]
    })
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn session_key_pre_op_prep_single_tx_failure() -> Result<()> {
    let key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    let session_key = KeyWith712Signer::random_session(KeyType::P256)?.unwrap();
    run_e2e_prep(|env| {
        vec![TxContext {
            authorization_keys: vec![&key],
            expected: ExpectedOutcome::FailEstimate,
            // Bundle session key authorization as a pre-op
            pre_ops: vec![TxContext {
                authorization_keys: vec![&session_key],
                key: Some(&key),
                // use random nonce sequence
                nonce: Some(U256::from_be_bytes(*B256::random()) << 64),
                ..Default::default()
            }],
            // Execute the transfer via session key in the same intent
            calls: vec![calls::transfer(env.erc20, Address::ZERO, U256::from(10000000u64))],
            // The intent is signed by the session key itself
            key: Some(&session_key),
            ..Default::default()
        }]
    })
    .await?;
    Ok(())
}
