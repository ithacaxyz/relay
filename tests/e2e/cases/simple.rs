//! Relay simple end-to-end test cases

use crate::e2e::{common_calls as calls, *};
use alloy::primitives::U256;
use eyre::Result;
use relay::{
    signers::DynSigner,
    types::{KeyType, KeyWith712Signer},
};

#[tokio::test(flavor = "multi_thread")]
async fn auth_then_erc20_transfer() -> Result<()> {
    for key_type in [KeyType::Secp256k1, KeyType::WebAuthnP256] {
        let key = KeyWith712Signer::random_admin(key_type)?.unwrap();

        // The first TX will bundle the prep/upgrade calls
        run_e2e(|env| {
            vec![
                TxContext {
                    authorization_keys: vec![key.to_authorized()],
                    expected: ExpectedOutcome::Pass,
                    auth: Some(AuthKind::Auth),
                    ..Default::default()
                },
                TxContext {
                    calls: vec![calls::transfer(env.erc20, Address::ZERO, U256::from(10))],
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
    let key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    run_e2e_upgraded(|_env| {
        vec![TxContext {
            authorization_keys: vec![key.to_authorized()],
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
    let dummy_signer =
        DynSigner::load("0x42424242428f97a5a0044266f0945389dc9e86dae88c7a8412f4603b6b78690d", None)
            .await?;

    run_e2e_upgraded(|_env| {
        vec![TxContext {
            authorization_keys: vec![key.to_authorized()],
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
                authorization_keys: vec![key1.to_authorized()],
                ..Default::default()
            },
            TxContext {
                expected: ExpectedOutcome::Pass,
                authorization_keys: vec![key2.to_authorized()],
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

    run_e2e(|env| {
        vec![
            // delegate, auth and set spend limit
            TxContext {
                expected: ExpectedOutcome::Pass,
                authorization_keys: vec![key1.to_authorized()],
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            // successful transfer
            TxContext {
                expected: ExpectedOutcome::Pass,
                calls: vec![calls::daily_limit(env.erc20, U256::from(15), key1.key())],
                key: Some(&key1),
                ..Default::default()
            },
            // overspend transfer should fail
            TxContext {
                expected: ExpectedOutcome::FailSend,
                calls: vec![calls::transfer(env.erc20, Address::ZERO, U256::from(100))],
                key: Some(&key1),
                ..Default::default()
            },
        ]
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn native_transfer() -> Result<()> {
    for key_type in [KeyType::Secp256k1, KeyType::P256, KeyType::WebAuthnP256] {
        let key = KeyWith712Signer::random_admin(key_type)?.unwrap();

        run_e2e(|_env| {
            vec![
                TxContext {
                    authorization_keys: vec![key.to_authorized()],
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
    let key1 = KeyWith712Signer::random_admin(KeyType::P256)?.unwrap();

    run_e2e(|env| {
        vec![
            TxContext {
                expected: ExpectedOutcome::Pass,
                authorization_keys: vec![key1.to_authorized()],
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            // successful transfer that should decrease the daily allowance
            TxContext {
                expected: ExpectedOutcome::Pass,
                calls: vec![
                    calls::daily_limit(env.erc20, U256::from(15), key1.key()),
                    calls::transfer(env.erc20, Address::ZERO, U256::from(10)),
                ],
                key: Some(&key1),
                ..Default::default()
            },
            // overspend transfer should fail
            TxContext {
                expected: ExpectedOutcome::FailSend,
                calls: vec![calls::transfer(env.erc20, Address::ZERO, U256::from(10))],
                key: Some(&key1),
                ..Default::default()
            },
        ]
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn spend_limits_bundle_failure() -> Result<()> {
    let key1 = KeyWith712Signer::random_admin(KeyType::P256)?.unwrap();

    run_e2e(|env| {
        vec![
            TxContext {
                expected: ExpectedOutcome::Pass,
                authorization_keys: vec![key1.to_authorized()],
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            // Bundled overspend should fail
            TxContext {
                expected: ExpectedOutcome::FailSend,
                calls: vec![
                    calls::daily_limit(env.erc20, U256::from(15), key1.key()),
                    calls::transfer(env.erc20, Address::ZERO, U256::from(20)),
                ],
                key: Some(&key1),
                ..Default::default()
            },
        ]
    })
    .await
}
