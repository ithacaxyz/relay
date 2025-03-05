//! Relay simple end-to-end test cases

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

#[tokio::test(flavor = "multi_thread")]
async fn auth_then_erc20_transfer() -> Result<()> {
    for key_type in [KeyType::Secp256k1, KeyType::P256, KeyType::WebAuthnP256] {
        let key = KeyWith712Signer::random_admin(key_type)?.unwrap();

        run_e2e(|env| {
            vec![
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
                TxContext {
                    calls: vec![Call {
                        target: env.erc20,
                        value: U256::ZERO,
                        data: MockErc20::transferCall {
                            recipient: Address::ZERO,
                            amount: U256::from(10),
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
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_auth_nonce() -> Result<()> {
    run_e2e(|env| {
        vec![TxContext {
            calls: vec![Call {
                target: env.eoa.address(),
                value: U256::ZERO,
                data: authorizeCall {
                    key: Key {
                        expiry: Default::default(),
                        keyType: KeyType::Secp256k1,
                        isSuperAdmin: true,
                        publicKey: env.eoa.address().abi_encode().into(),
                    },
                }
                .abi_encode()
                .into(),
            }],
            expected: ExpectedOutcome::FailSend,
            auth: Some(AuthKind::modified_nonce(123)),
            ..Default::default()
        }]
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_auth_signature() -> Result<()> {
    let dummy_signer =
        DynSigner::load("0x42424242428f97a5a0044266f0945389dc9e86dae88c7a8412f4603b6b78690d", None)
            .await?;

    run_e2e(|env| {
        vec![TxContext {
            calls: vec![Call {
                target: env.eoa.address(),
                value: U256::ZERO,
                data: authorizeCall {
                    key: Key {
                        expiry: Default::default(),
                        keyType: KeyType::Secp256k1,
                        isSuperAdmin: true,
                        publicKey: env.eoa.address().abi_encode().into(),
                    },
                }
                .abi_encode()
                .into(),
            }],
            expected: ExpectedOutcome::FailSend,
            // Signing with an unrelated key should fail during sendAction when calling eth_call
            auth: Some(AuthKind::modified_signer(dummy_signer)),
            ..Default::default()
        }]
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_auth_quote_check() -> Result<()> {
    let env = Environment::setup_with_upgraded().await?;
    let tx = TxContext {
        calls: vec![Call {
            target: env.eoa.address(),
            value: U256::ZERO,
            data: authorizeCall {
                key: Key {
                    expiry: Default::default(),
                    keyType: KeyType::Secp256k1,
                    isSuperAdmin: true,
                    publicKey: env.eoa.address().abi_encode().into(),
                },
            }
            .abi_encode()
            .into(),
        }],
        expected: ExpectedOutcome::Pass,
        auth: Some(AuthKind::Auth),
        ..Default::default()
    };

    let ActionRequest { action, mut authorization, quote } =
        prepare_action_request(0, &tx, &env).await?.expect("should not fail");

    // If the quote authorization item is different than the one passed to the action, fail.
    assert!(quote.ty().authorization_address.is_some());
    authorization = None;
    assert!(env.relay_endpoint.send_action(action, quote, authorization).await.is_err());

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_then_two_authorizes_then_erc20_transfer() -> Result<()> {
    let key1 = KeyWith712Signer::random_admin(KeyType::P256)?.unwrap();
    let key2 = KeyWith712Signer::random_admin(KeyType::P256)?.unwrap();

    run_e2e(|env| {
        vec![
            TxContext {
                expected: ExpectedOutcome::Pass,
                calls: vec![],
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            TxContext {
                expected: ExpectedOutcome::Pass,
                calls: vec![Call {
                    target: env.eoa.address(),
                    value: U256::ZERO,
                    data: authorizeCall { key: key1.clone() }.abi_encode().into(),
                }],
                ..Default::default()
            },
            TxContext {
                expected: ExpectedOutcome::Pass,
                calls: vec![Call {
                    target: env.eoa.address(),
                    value: U256::ZERO,
                    data: authorizeCall { key: key2.clone() }.abi_encode().into(),
                }],
                key: Some(&key1),
                ..Default::default()
            },
            TxContext {
                expected: ExpectedOutcome::Pass,
                calls: vec![Call {
                    target: env.erc20,
                    value: U256::ZERO,
                    data: MockErc20::transferCall {
                        recipient: Address::ZERO,
                        amount: U256::from(10),
                    }
                    .abi_encode()
                    .into(),
                }],
                key: Some(&key2),
                ..Default::default()
            },
        ]
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn spend_limits() -> Result<()> {
    let key1 = KeyWith712Signer::random_admin(KeyType::P256)?.unwrap();

    run_e2e(|env| {
        vec![
            // delegate, auth and set spend limit
            TxContext {
                expected: ExpectedOutcome::Pass,
                calls: vec![
                    Call {
                        target: env.eoa.address(),
                        value: U256::ZERO,
                        data: authorizeCall { key: key1.clone() }.abi_encode().into(),
                    },
                    Call {
                        target: env.eoa.address(),
                        value: U256::ZERO,
                        data: Delegation::setSpendLimitCall {
                            keyHash: key1.key_hash(),
                            token: env.erc20,
                            period: SpendPeriod::Day,
                            limit: U256::from(15),
                        }
                        .abi_encode()
                        .into(),
                    },
                ],
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            // succesful transfer
            TxContext {
                expected: ExpectedOutcome::Pass,
                calls: vec![Call {
                    target: env.erc20,
                    value: U256::ZERO,
                    data: MockErc20::transferCall {
                        recipient: Address::ZERO,
                        amount: U256::from(10),
                    }
                    .abi_encode()
                    .into(),
                }],
                key: Some(&key1),
                ..Default::default()
            },
            // spend limit exceeded (20 wei exp > 15 wei exp)
            TxContext {
                expected: ExpectedOutcome::FailSend, // todo this should fail on estimate
                calls: vec![Call {
                    target: env.erc20,
                    value: U256::ZERO,
                    data: MockErc20::transferCall {
                        recipient: Address::ZERO,
                        amount: U256::from(10),
                    }
                    .abi_encode()
                    .into(),
                }],
                key: Some(&key1),
                ..Default::default()
            },
        ]
    })
    .await
}
