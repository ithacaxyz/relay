//! Relay simple end-to-end test cases

use crate::e2e::*;
use alloy::{
    hex,
    primitives::{b256, Bytes, B256, U256},
    sol_types::{SolCall, SolValue},
};
use eyre::Result;
use relay::{
    signer::DynSigner,
    types::{Call, IDelegation::authorizeCall, Key, KeyType},
};

#[tokio::test(flavor = "multi_thread")]
async fn auth_then_total_supply() -> Result<()> {
    let test_vector = vec![
        TxContext {
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
        },
        TxContext {
            calls: vec![Call {
                target: FAKE_ERC20,
                value: U256::ZERO,
                data: Bytes::from(hex::decode("0x18160ddd").unwrap()),
            }],
            expected: ExpectedOutcome::Pass,
            auth: None,
        },
    ];

    run_e2e(test_vector).await
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
    }];

    run_e2e(test_vector).await
}
