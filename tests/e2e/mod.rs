//! Relay end-to-end tests
#![allow(unused)]

mod cases;
mod constants;
mod environment;
mod types;

pub use constants::*;
use environment::*;
pub use types::*;

use alloy::{
    primitives::{bytes, Address, Bytes, U256},
    providers::{PendingTransactionBuilder, Provider},
    signers::Signer,
    sol_types::{SolCall, SolConstructor, SolEvent, SolValue},
};
use eyre::Result;
use relay::{
    rpc::RelayApiClient,
    types::{Action, Key, KeyType, PartialAction, PartialUserOp, Signature, UserOp},
};

/// Executes all test cases using the refactored environment and test case processors.
/// If any test case returns an error, ensures the relay task is shutdown before returning the
/// error.
pub async fn run_e2e(txs: Vec<TxContext>) -> Result<()> {
    let env = Environment::setup().await?;
    let result = async {
        for (nonce, tx) in txs.into_iter().enumerate() {
            process_tx_case(nonce, tx, &env).await?;
        }
        Ok(())
    }
    .await;

    env.cleanup().await;
    result
}

/// Processes a single test case, returning an error on failure.
async fn process_tx_case(nonce: usize, tx: TxContext, env: &Environment) -> Result<()> {
    let execution_data: Bytes = tx.calls.abi_encode().into();
    let auth =
        if let Some(auth) = tx.auth {
            let nonce_val = match auth {
                AuthKind::Auth => nonce as u64,
                AuthKind::AuthWithNonce(n) => n,
            };
            let auth_struct = alloy::eips::eip7702::Authorization {
                chain_id: U256::from(0),
                address: env.delegation,
                nonce: nonce_val,
            };
            let auth_hash = auth_struct.signature_hash();

            Some(auth_struct.into_signed(
                env.eoa_signer.sign_hash(&auth_hash).await.expect("Auth signing failed"),
            ))
        } else {
            None
        };

    let quote = env
        .relay_endpoint
        .estimate_fee(
            PartialAction {
                op: PartialUserOp {
                    eoa: env.eoa_signer.address(),
                    executionData: execution_data.clone(),
                    nonce: U256::from(nonce),
                },
                auth: auth.as_ref().map(|auth| *auth.address()),
            },
            env.erc20,
        )
        .await;

    if quote.is_err() {
        if tx.expected.failed_estimate() {
            return Ok(());
        } else {
            return Err(eyre::eyre!("Fee estimation error for nonce {nonce}: {quote:?}"));
        }
    }

    let quote = quote?;
    let mut op = UserOp {
        eoa: env.eoa_signer.address(),
        executionData: execution_data.clone(),
        nonce: U256::from(nonce),
        payer: Address::ZERO,
        paymentToken: env.erc20,
        paymentRecipient: Address::ZERO,
        paymentAmount: U256::ZERO,
        paymentMaxAmount: U256::ZERO,
        paymentPerGas: U256::ZERO,
        combinedGas: U256::from(quote.ty().gas_estimate),
        signature: bytes!(""),
    };

    let digest = op
        .eip712_digest(env.entrypoint, env.chain_id, U256::ZERO)
        .expect("Failed to create digest");
    let signature = env.eoa_signer.sign_hash(&digest).await.expect("Signing failed");

    op.signature = if nonce == 0 {
        signature.as_bytes().into()
    } else {
        Signature {
            innerSignature: signature.as_bytes().into(),
            keyHash: Key {
                expiry: Default::default(),
                keyType: KeyType::Secp256k1,
                isSuperAdmin: true,
                publicKey: env.eoa_signer.address().abi_encode().into(),
            }
            .key_hash(),
            prehash: false,
        }
        .abi_encode_packed()
        .into()
    };

    let action = Action { op, auth };

    match env.relay_endpoint.send_action(action, quote).await {
        Ok(tx_hash) => {
            if tx.expected.failed_send() {
                return Err(eyre::eyre!(
                    "Send action nonce {nonce} passed when it should have failed.",
                ));
            }

            let receipt = PendingTransactionBuilder::new(env.provider.root().clone(), tx_hash)
                .get_receipt()
                .await
                .expect("Failed to get receipt");

            if receipt.status() {
                if tx.expected.reverted_tx() {
                    return Err(eyre::eyre!(
                        "Transaction nonce {nonce} passed when it should have reverted.",
                    ));
                }
            } else if !tx.expected.reverted_tx() {
                return Err(eyre::eyre!("Transaction failed for nonce {nonce}: {receipt:?}"));
            }

            // UserOp has succeeded if the nonce has been invalidated.
            let nonce_invalidated = receipt.inner.logs().iter().any(|log| {
                log.topic0()
                    .is_some_and(|topic| topic == &Delegation::NonceInvalidated::SIGNATURE_HASH)
            });
            if nonce_invalidated {
                if tx.expected.failed_user_op() {
                    return Err(eyre::eyre!(
                        "UserOp nonce {nonce} passed when it should have failed."
                    ));
                }
            } else if !tx.expected.failed_user_op() {
                return Err(eyre::eyre!(
                    "Transaction succeeded but UserOp failed for nonce {nonce}",
                ));
            }
        }
        Err(_) => {
            if tx.expected.failed_send() {
                return Ok(());
            }
            return Err(eyre::eyre!("Send error for nonce {nonce}"));
        }
    }

    Ok(())
}
