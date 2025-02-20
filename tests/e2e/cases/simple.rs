//! Relay simple end-to-end test cases

use crate::e2e::*;
use alloy::{
    hex,
    primitives::{b256, Bytes, B256, U256},
    sol_types::{SolCall, SolValue},
};
use eyre::Result;
use relay::{
    error::SendActionError,
    signers::{DynSigner, P256Signer},
    types::{Call, IDelegation::authorizeCall, Key, KeyType, KeyWith712Signer},
};

#[tokio::test(flavor = "multi_thread")]
async fn auth_then_erc20_transfer() -> Result<()> {
    let eoa_signer = DynSigner::load(&EOA_PRIVATE_KEY.to_string(), None).await?;
    let expiry = U40::ZERO;
    let super_admin = true;

    for key_type in [KeyType::Secp256k1, KeyType::P256, KeyType::WebAuthnP256] {
        let key_with_signer = KeyWith712Signer::random(key_type)?.unwrap();

        let test_vector = vec![
            TxContext {
                calls: vec![Call {
                    target: EOA_ADDRESS,
                    value: U256::ZERO,
                    data: authorizeCall { key: key_with_signer.key.clone() }.abi_encode().into(),
                }],
                expected: ExpectedOutcome::Pass,
                auth: Some(AuthKind::Auth),
                ..Default::default()
            },
            TxContext {
                calls: vec![Call {
                    target: FAKE_ERC20,
                    value: U256::ZERO,
                    data: MockErc20::transferCall {
                        recipient: Address::ZERO,
                        amount: U256::from(10),
                    }
                    .abi_encode()
                    .into(),
                }],
                expected: ExpectedOutcome::Pass,
                key: Some(key_with_signer),
                ..Default::default()
            },
        ];

        run_e2e(test_vector).await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_auth_nonce() -> Result<()> {
    let test_vector = vec![TxContext {
        calls: vec![Call {
            target: EOA_ADDRESS,
            value: U256::ZERO,
            data: authorizeCall {
                key: Key {
                    expiry: Default::default(),
                    keyType: KeyType::Secp256k1,
                    isSuperAdmin: true,
                    publicKey: EOA_ADDRESS.abi_encode().into(),
                },
            }
            .abi_encode()
            .into(),
        }],
        expected: ExpectedOutcome::FailSend,
        auth: Some(AuthKind::modified_nonce(123)),
        ..Default::default()
    }];

    run_e2e(test_vector).await
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_auth_signature() -> Result<()> {
    let test_vector = vec![TxContext {
        calls: vec![Call {
            target: EOA_ADDRESS,
            value: U256::ZERO,
            data: authorizeCall {
                key: Key {
                    expiry: Default::default(),
                    keyType: KeyType::Secp256k1,
                    isSuperAdmin: true,
                    publicKey: EOA_ADDRESS.abi_encode().into(),
                },
            }
            .abi_encode()
            .into(),
        }],
        expected: ExpectedOutcome::FailSend,
        // Signing with an unrelated key should fail during sendAction when calling eth_call
        auth: Some(AuthKind::modified_signer(
            DynSigner::load(
                "0x42424242428f97a5a0044266f0945389dc9e86dae88c7a8412f4603b6b78690d",
                None,
            )
            .await?,
        )),
        ..Default::default()
    }];

    run_e2e(test_vector).await
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_auth_quote_check() -> Result<()> {
    let tx = TxContext {
        calls: vec![Call {
            target: EOA_ADDRESS,
            value: U256::ZERO,
            data: authorizeCall {
                key: Key {
                    expiry: Default::default(),
                    keyType: KeyType::Secp256k1,
                    isSuperAdmin: true,
                    publicKey: EOA_ADDRESS.abi_encode().into(),
                },
            }
            .abi_encode()
            .into(),
        }],
        expected: ExpectedOutcome::Pass,
        auth: Some(AuthKind::Auth),
        ..Default::default()
    };

    let env = Environment::setup().await?;

    let ActionRequest { action, mut authorization, quote } =
        prepare_action_request(0, &tx, &env).await?.expect("should not fail");

    // If the quote authorization item is different than the one passed to the action, fail.
    assert!(quote.ty().authorization_address.is_some());
    authorization = None;
    assert!(env.relay_endpoint.send_action(action, quote, authorization).await.is_err());

    Ok(())
}
