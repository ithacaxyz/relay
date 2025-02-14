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
    dyn_abi::Eip712Domain,
    primitives::{bytes, Address, Bytes, U256},
    providers::{PendingTransactionBuilder, Provider},
    signers::Signer,
    sol_types::{SolCall, SolConstructor, SolEvent, SolValue},
};
use eyre::{Context, Result};
use relay::{
    rpc::RelayApiClient,
    types::{Action, Entry, Key, KeyType, PartialAction, PartialUserOp, Signature, UserOp},
};

/// Executes all transactions from the test case. If it returns an error, ensures the relay task is
/// shutdown first.
pub async fn run_e2e(txs: Vec<TxContext>) -> Result<()> {
    let env = Environment::setup().await?;
    let result = async {
        for (nonce, tx) in txs.into_iter().enumerate() {
            process_tx(nonce, tx, &env).await?;
        }
        Ok(())
    }
    .await;

    env.cleanup().await;
    result
}

/// Processes a single transaction, returning an error on failure.
///
/// The process follows these steps:
/// 1. Prepares execution data and authorization (if required):
///    - Encodes the transaction calls
///    - Creates and signs an EIP-7702 authorization if specified
///
/// 2. Estimates fees through the relay:
///    - Sends a fee estimation request with the partial user operation
///    - Handles expected estimation failures
///
/// 3. Constructs the full UserOp:
///    - Sets basic parameters (EOA, execution data, nonce)
///    - Initializes payment-related fields
///    - Sets gas parameters based on the quote
///
/// 4. Signs the UserOp:
///    - Creates an EIP-712 digest of the operation
///    - Signs with EOA signer
///    - For nonce 0: uses raw signature
///    - For other nonces: wraps signature with key information
///
/// 5. Submits and verifies execution:
///    - Sends the action to the relay
///    - Handles expected send failures
///    - Retrieves and checks transaction receipt
///    - Verifies transaction status matches expectations
///    - Confirms UserOp success by checking nonce invalidation
async fn process_tx(nonce: usize, tx: TxContext, env: &Environment) -> Result<()> {
    let execution_data: Bytes = tx.calls.abi_encode().into();
    let auth = if let Some(auth) = tx.auth {
        let auth_struct = alloy::eips::eip7702::Authorization {
            chain_id: U256::from(0),
            address: env.delegation,
            nonce: auth.nonce().unwrap_or(nonce as u64),
        };
        let auth_hash = auth_struct.signature_hash();

        Some(auth_struct.into_signed(
            env.eoa_signer.sign_hash(&auth_hash).await.wrap_err("Auth signing failed")?,
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

    let entry = Entry::new(env.entrypoint, env.provider.root());
    let signature = env
        .eoa_signer
        .sign_typed_data(
            &op.as_eip712(U256::ZERO).unwrap(),
            &entry.eip712_domain(op.is_multichain()).await.unwrap(),
        )
        .await
        .wrap_err("Signing failed")?;

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
                .wrap_err("Failed to get receipt")?;

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
