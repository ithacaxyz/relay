//! Porto equivalent end-to-end test cases

use crate::e2e::*;
use alloy::{
    hex,
    primitives::{B256, Bytes, FixedBytes, U256, address, b256, fixed_bytes},
    sol_types::{SolCall, SolValue},
};
use eyre::Result;
use relay::{
    error::SendActionError,
    signers::{DynSigner, P256Signer},
    types::{
        Call, Delegation::SpendPeriod, IDelegation::authorizeCall, Key, KeyType, KeyWith712Signer,
    },
};

/// porto test: "behavior: delegation"
#[tokio::test(flavor = "multi_thread")]
async fn behavior_delegation() -> Result<()> {
    let key = KeyWith712Signer::random_admin(KeyType::P256)?.unwrap();
    run_e2e(|env| {
        vec![
            // Authorize key (delegation provided in the call)
            TxContext {
                calls: vec![Call {
                    target: env.eoa.address(),
                    value: U256::ZERO,
                    data: authorizeCall { key: key.clone() }.abi_encode().into(),
                }],
                expected: ExpectedOutcome::Pass,
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            // Perform a transfer signed by the authorized key
            TxContext {
                calls: vec![Call {
                    target: env.erc20,
                    value: U256::ZERO,
                    data: MockErc20::transferCall {
                        recipient: Address::ZERO,
                        amount: U256::from(100_000_000_000_000u64),
                    }
                    .abi_encode()
                    .into(),
                }],
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
    let key = KeyWith712Signer::random_admin(KeyType::P256)?.unwrap();
    let another_key = KeyWith712Signer::random_session(KeyType::P256)?.unwrap();
    run_e2e(|env| {
        vec![
            // Authorize admin key
            TxContext {
                calls: vec![Call {
                    target: env.eoa.address(),
                    value: U256::ZERO,
                    data: authorizeCall { key: key.clone() }.abi_encode().into(),
                }],
                expected: ExpectedOutcome::Pass,
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            // Authorize another key, set execution guard and spend limit (1.5 ETH) for it
            TxContext {
                calls: vec![
                    Call {
                        target: env.eoa.address(),
                        value: U256::ZERO,
                        data: authorizeCall { key: another_key.clone() }.abi_encode().into(),
                    },
                    Call {
                        target: env.eoa.address(),
                        value: U256::ZERO,
                        data: Delegation::setCanExecuteCall {
                            keyHash: another_key.key_hash(),
                            can: true,
                            fnSel: DEFAULT_EXECUTE_SELECTOR,
                            target: DEFAULT_EXECUTE_TO,
                        }
                        .abi_encode()
                        .into(),
                    },
                    Call {
                        target: env.eoa.address(),
                        value: U256::ZERO,
                        data: Delegation::setSpendLimitCall {
                            keyHash: another_key.key_hash(),
                            token: env.erc20,
                            period: Delegation::SpendPeriod::Day,
                            limit: U256::from(1_500_000_000_000_000_000u64),
                        }
                        .abi_encode()
                        .into(),
                    },
                ],
                expected: ExpectedOutcome::Pass,
                ..Default::default()
            },
            // Successful transfer of 1 ETH
            TxContext {
                calls: vec![Call {
                    target: env.erc20,
                    value: U256::ZERO,
                    data: MockErc20::transferCall {
                        recipient: Address::ZERO,
                        amount: U256::from(1_000_000_000_000_000_000u64),
                    }
                    .abi_encode()
                    .into(),
                }],
                expected: ExpectedOutcome::Pass,
                key: Some(&another_key),
                ..Default::default()
            },
            // Another transfer of 1 ETH exceeds spend limit → fail
            TxContext {
                calls: vec![Call {
                    target: env.erc20,
                    value: U256::ZERO,
                    data: MockErc20::transferCall {
                        recipient: Address::ZERO,
                        amount: U256::from(1_000_000_000_000_000_000u64),
                    }
                    .abi_encode()
                    .into(),
                }],
                expected: ExpectedOutcome::FailSend,
                key: Some(&another_key),
                ..Default::default()
            },
        ]
    })
    .await?;
    Ok(())
}

/// porto test: "behavior: spend limits"
#[tokio::test(flavor = "multi_thread")]
async fn behavior_spend_limits() -> Result<()> {
    let key = KeyWith712Signer::random_admin(KeyType::P256)?.unwrap();
    run_e2e(|env| {
        vec![
            // Delegate, authorize and set spend limit (1.5 ETH) in one call
            TxContext {
                calls: vec![
                    Call {
                        target: env.eoa.address(),
                        value: U256::ZERO,
                        data: authorizeCall { key: key.clone() }.abi_encode().into(),
                    },
                    Call {
                        target: env.eoa.address(),
                        value: U256::ZERO,
                        data: Delegation::setSpendLimitCall {
                            keyHash: key.key_hash(),
                            token: env.erc20,
                            period: Delegation::SpendPeriod::Day,
                            limit: U256::from(1_500_000_000_000_000_000u64), // 1.5 ETH in wei
                        }
                        .abi_encode()
                        .into(),
                    },
                ],
                expected: ExpectedOutcome::Pass,
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            // Successful transfer of 1 ETH
            TxContext {
                calls: vec![Call {
                    target: env.erc20,
                    value: U256::ZERO,
                    data: MockErc20::transferCall {
                        recipient: Address::ZERO,
                        amount: U256::from(1_000_000_000_000_000_000u64), // 1 ETH
                    }
                    .abi_encode()
                    .into(),
                }],
                expected: ExpectedOutcome::Pass,
                key: Some(&key),
                ..Default::default()
            },
            // Another transfer of 1 ETH exceeds the 1.5 ETH limit → fail
            TxContext {
                calls: vec![Call {
                    target: env.erc20,
                    value: U256::ZERO,
                    data: MockErc20::transferCall {
                        recipient: Address::ZERO,
                        amount: U256::from(1_000_000_000_000_000_000u64),
                    }
                    .abi_encode()
                    .into(),
                }],
                expected: ExpectedOutcome::FailSend,
                key: Some(&key),
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
    let key = KeyWith712Signer::random_admin(KeyType::P256)?.unwrap();
    let another_key = KeyWith712Signer::random_session(KeyType::P256)?.unwrap();

    run_e2e(|env| {
        vec![
            // Authorize admin key
            TxContext {
                calls: vec![Call {
                    target: env.eoa.address(),
                    value: U256::ZERO,
                    data: authorizeCall { key: key.clone() }.abi_encode().into(),
                }],
                expected: ExpectedOutcome::Pass,
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            // Authorize another key and set execution guard with a target scope (only env.erc20
            // allowed)
            TxContext {
                calls: vec![
                    Call {
                        target: env.eoa.address(),
                        value: U256::ZERO,
                        data: authorizeCall { key: another_key.clone() }.abi_encode().into(),
                    },
                    Call {
                        target: env.eoa.address(),
                        value: U256::ZERO,
                        data: Delegation::setCanExecuteCall {
                            keyHash: another_key.key_hash(),
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
                calls: vec![Call {
                    target: env.erc20,
                    value: U256::ZERO,
                    data: MockErc20::transferCall {
                        recipient: Address::ZERO,
                        amount: U256::from(100_000_000_000_000u64),
                    }
                    .abi_encode()
                    .into(),
                }],
                expected: ExpectedOutcome::Pass,
                key: Some(&another_key),
                ..Default::default()
            },
            // Failing transfer (different target)
            TxContext {
                calls: vec![Call {
                    target: env.erc20_alt, // assume this is a different contract address
                    value: U256::ZERO,
                    data: MockErc20::transferCall {
                        recipient: Address::ZERO,
                        amount: U256::from(100_000_000_000_000u64),
                    }
                    .abi_encode()
                    .into(),
                }],
                expected: ExpectedOutcome::FailSend,
                key: Some(&another_key),
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
    let key = KeyWith712Signer::random_admin(KeyType::P256)?.unwrap();
    let another_key = KeyWith712Signer::random_session(KeyType::P256)?.unwrap();
    run_e2e(|env| {
        vec![
            // Authorize admin key
            TxContext {
                calls: vec![Call {
                    target: env.eoa.address(),
                    value: U256::ZERO,
                    data: authorizeCall { key: key.clone() }.abi_encode().into(),
                }],
                expected: ExpectedOutcome::Pass,
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            // Authorize another key and set execution guard with target and selector (for
            // "transfer")
            TxContext {
                calls: vec![
                    Call {
                        target: env.eoa.address(),
                        value: U256::ZERO,
                        data: authorizeCall { key: another_key.clone() }.abi_encode().into(),
                    },
                    Call {
                        target: env.eoa.address(),
                        value: U256::ZERO,
                        data: Delegation::setCanExecuteCall {
                            keyHash: another_key.key_hash(),
                            can: true,
                            fnSel: MockErc20::transferCall::SELECTOR.into(),
                            target: env.erc20,
                        }
                        .abi_encode()
                        .into(),
                    },
                ],
                expected: ExpectedOutcome::Pass,
                ..Default::default()
            },
            // Valid transfer call using "transfer"
            TxContext {
                calls: vec![Call {
                    target: env.erc20,
                    value: U256::ZERO,
                    data: MockErc20::transferCall {
                        recipient: Address::ZERO,
                        amount: U256::from(100_000_000_000_000u64),
                    }
                    .abi_encode()
                    .into(),
                }],
                expected: ExpectedOutcome::Pass,
                key: Some(&another_key),
                ..Default::default()
            },
            // Failing call using a different selector (e.g. "mint")
            TxContext {
                calls: vec![Call {
                    target: env.erc20,
                    value: U256::ZERO,
                    data: MockErc20::mintCall {
                        a: Address::ZERO,
                        val: U256::from(100_000_000_000_000u64),
                    }
                    .abi_encode()
                    .into(),
                }],
                expected: ExpectedOutcome::FailSend,
                key: Some(&another_key),
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
    run_e2e(|env| {
        vec![
            // Delegate (empty calls with auth)
            TxContext {
                calls: vec![],
                expected: ExpectedOutcome::Pass,
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            // Transfer call: transfer 0.0001 ETH worth (using a placeholder value)
            TxContext {
                calls: vec![Call {
                    target: env.erc20,
                    value: U256::ZERO,
                    data: MockErc20::transferCall {
                        recipient: Address::ZERO, // using ZERO as a stand-in for a random address
                        amount: U256::from(100_000_000_000_000u64), // ≈0.0001 ETH in wei
                    }
                    .abi_encode()
                    .into(),
                }],
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
    let key = KeyWith712Signer::random_admin(KeyType::P256)?.unwrap();
    let another_key = KeyWith712Signer::random_session(KeyType::P256)?.unwrap();
    run_e2e(|env| {
        vec![
            // Authorize admin key with delegation
            TxContext {
                calls: vec![Call {
                    target: env.eoa.address(),
                    value: U256::ZERO,
                    data: authorizeCall { key: key.clone() }.abi_encode().into(),
                }],
                expected: ExpectedOutcome::Pass,
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            // Authorize and set execution guard using default values for selector and target
            TxContext {
                calls: vec![
                    Call {
                        target: env.eoa.address(),
                        value: U256::ZERO,
                        data: authorizeCall { key: another_key.clone() }.abi_encode().into(),
                    },
                    Call {
                        target: env.eoa.address(),
                        value: U256::ZERO,
                        data: Delegation::setCanExecuteCall {
                            keyHash: another_key.key_hash(),
                            can: true,
                            fnSel: DEFAULT_EXECUTE_SELECTOR,
                            target: DEFAULT_EXECUTE_TO,
                        }
                        .abi_encode()
                        .into(),
                    },
                ],
                expected: ExpectedOutcome::Pass,
                ..Default::default()
            },
            // Transfer signed by the second key
            TxContext {
                calls: vec![Call {
                    target: env.erc20,
                    value: U256::ZERO,
                    data: MockErc20::transferCall {
                        recipient: Address::ZERO,
                        amount: U256::from(100_000_000_000_000u64),
                    }
                    .abi_encode()
                    .into(),
                }],
                expected: ExpectedOutcome::Pass,
                key: Some(&another_key),
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
    run_e2e(|env| {
        vec![
            // Delegate
            TxContext {
                calls: vec![],
                expected: ExpectedOutcome::Pass,
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            // Prepared transfer call (simulating prepare then sendPrepared)
            TxContext {
                calls: vec![Call {
                    target: env.erc20,
                    value: U256::ZERO,
                    data: MockErc20::transferCall {
                        recipient: Address::ZERO,
                        amount: U256::from(100_000_000_000_000u64),
                    }
                    .abi_encode()
                    .into(),
                }],
                expected: ExpectedOutcome::Pass,
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
    let key = KeyWith712Signer::random_admin(KeyType::P256)?.unwrap();
    run_e2e(|env| {
        vec![
            // Send authorize call (EOA signs; delegation parameter provided)
            TxContext {
                calls: vec![Call {
                    target: env.eoa.address(),
                    value: U256::ZERO,
                    data: authorizeCall { key: key.clone() }.abi_encode().into(),
                }],
                expected: ExpectedOutcome::Pass,
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            // Transfer call signed by the newly authorized key
            TxContext {
                calls: vec![Call {
                    target: env.erc20,
                    value: U256::ZERO,
                    data: MockErc20::transferCall {
                        recipient: Address::ZERO,
                        amount: U256::from(100_000_000_000_000u64),
                    }
                    .abi_encode()
                    .into(),
                }],
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
    let key = KeyWith712Signer::random_admin(KeyType::P256)?.unwrap();
    run_e2e(|env| {
        vec![
            // Delegate first
            TxContext {
                calls: vec![],
                expected: ExpectedOutcome::Pass,
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            // Then authorize the new key (signed by EOA)
            TxContext {
                calls: vec![Call {
                    target: env.eoa.address(),
                    value: U256::ZERO,
                    data: authorizeCall { key: key.clone() }.abi_encode().into(),
                }],
                expected: ExpectedOutcome::Pass,
                ..Default::default()
            },
            // Transfer call signed by the authorized key
            TxContext {
                calls: vec![Call {
                    target: env.erc20,
                    value: U256::ZERO,
                    data: MockErc20::transferCall {
                        recipient: Address::ZERO,
                        amount: U256::from(100_000_000_000_000u64),
                    }
                    .abi_encode()
                    .into(),
                }],
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
    let key = KeyWith712Signer::random_admin(KeyType::P256)?.unwrap();
    let another_key = KeyWith712Signer::random_admin(KeyType::P256)?.unwrap();
    run_e2e(|env| {
        vec![
            // Delegate
            TxContext {
                calls: vec![],
                expected: ExpectedOutcome::Pass,
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            // Authorize first key using EOA
            TxContext {
                calls: vec![Call {
                    target: env.eoa.address(),
                    value: U256::ZERO,
                    data: authorizeCall { key: key.clone() }.abi_encode().into(),
                }],
                expected: ExpectedOutcome::Pass,
                ..Default::default()
            },
            // Authorize a second (P256) key using the first key
            TxContext {
                calls: vec![Call {
                    target: env.eoa.address(),
                    value: U256::ZERO,
                    data: authorizeCall { key: another_key.clone() }.abi_encode().into(),
                }],
                expected: ExpectedOutcome::Pass,
                key: Some(&key),
                ..Default::default()
            },
            // Transfer using the second key
            TxContext {
                calls: vec![Call {
                    target: env.erc20,
                    value: U256::ZERO,
                    data: MockErc20::transferCall {
                        recipient: Address::ZERO,
                        amount: U256::from(100_000_000_000_000u64),
                    }
                    .abi_encode()
                    .into(),
                }],
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
    let key = KeyWith712Signer::random_admin(KeyType::P256)?.unwrap();
    // Create a session key (using P256 again)
    let session_key = KeyWith712Signer::random_session(KeyType::P256)?.unwrap();
    run_e2e(|env| {
        vec![
            // Delegate
            TxContext {
                calls: vec![],
                expected: ExpectedOutcome::Pass,
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            // Authorize the admin key (P256)
            TxContext {
                calls: vec![Call {
                    target: env.eoa.address(),
                    value: U256::ZERO,
                    data: authorizeCall { key: key.clone() }.abi_encode().into(),
                }],
                expected: ExpectedOutcome::Pass,
                ..Default::default()
            },
            // Authorize the session key and set its execution guard using
            // Delegation::setCanExecuteCall with defaults
            TxContext {
                calls: vec![
                    Call {
                        target: env.eoa.address(),
                        value: U256::ZERO,
                        data: authorizeCall { key: session_key.clone() }.abi_encode().into(),
                    },
                    Call {
                        target: env.eoa.address(),
                        value: U256::ZERO,
                        data: Delegation::setCanExecuteCall {
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
                calls: vec![Call {
                    target: env.erc20,
                    value: U256::ZERO,
                    data: MockErc20::transferCall {
                        recipient: Address::ZERO,
                        amount: U256::from(100_000_000_000_000u64),
                    }
                    .abi_encode()
                    .into(),
                }],
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
    let key = KeyWith712Signer::random_admin(KeyType::P256)?.unwrap();
    let another_key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    run_e2e(|env| {
        vec![
            // Delegate
            TxContext {
                calls: vec![],
                expected: ExpectedOutcome::Pass,
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            // Authorize the first key (P256)
            TxContext {
                calls: vec![Call {
                    target: env.eoa.address(),
                    value: U256::ZERO,
                    data: authorizeCall { key: key.clone() }.abi_encode().into(),
                }],
                expected: ExpectedOutcome::Pass,
                ..Default::default()
            },
            // Authorize the second key (WebCryptoP256) using the first key
            TxContext {
                calls: vec![Call {
                    target: env.eoa.address(),
                    value: U256::ZERO,
                    data: authorizeCall { key: another_key.clone() }.abi_encode().into(),
                }],
                expected: ExpectedOutcome::Pass,
                key: Some(&key),
                ..Default::default()
            },
            // Transfer signed by the second key
            TxContext {
                calls: vec![Call {
                    target: env.erc20,
                    value: U256::ZERO,
                    data: MockErc20::transferCall {
                        recipient: Address::ZERO,
                        amount: U256::from(100_000_000_000_000u64),
                    }
                    .abi_encode()
                    .into(),
                }],
                expected: ExpectedOutcome::Pass,
                key: Some(&another_key),
                ..Default::default()
            },
        ]
    })
    .await?;
    Ok(())
}
