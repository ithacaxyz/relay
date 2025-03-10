//! Relay end-to-end tests
#![allow(unused)]

mod cases;
mod common_calls;
mod constants;
mod environment;
mod eoa;
mod types;

use cases::{prep_account, upgrade_account};
pub use constants::*;
use environment::*;
use jsonrpsee::core::RpcResult;
pub use types::*;

use alloy::{
    dyn_abi::Eip712Domain,
    eips::eip7702::{SignedAuthorization, constants::EIP7702_DELEGATION_DESIGNATOR},
    primitives::{Address, B256, Bytes, TxHash, U256, bytes},
    providers::{PendingTransactionBuilder, Provider},
    signers::Signer,
    sol_types::{SolCall, SolConstructor, SolEvent, SolStruct, SolValue},
    uint,
};
use eyre::{Context, OptionExt, Result};
use relay::{
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    types::{
        Action, CreateAccountCapabilities, Delegation, ENTRYPOINT_NO_ERROR, Entry, Key, KeyType,
        KeyWith712Signer, PartialAction, PartialUserOp, PrepareCallsCapabilities,
        PrepareCallsParameters, PrepareCallsResponse, PrepareUpgradeAccountParameters,
        SendPreparedCallsParameters, SendPreparedCallsResponse, SendPreparedCallsSignature,
        Signature, SignedQuote, U40, UpgradeAccountParameters, UserOp, WebAuthnP256,
        capabilities::{AuthorizeKey, Meta},
    },
};
use std::str::FromStr;

/// Executes all transactions from the test case with both [`run_e2e_upgraded`] and
/// [`run_e2e_prep`].
pub async fn run_e2e<'a, F>(build_txs: F) -> Result<()>
where
    F: Fn(&Environment) -> Vec<TxContext<'a>>,
{
    run_e2e_upgraded(&build_txs).await?;
    if std::env::var("TEST_CI_FORK").is_ok() {
        // Test WILL run on a local envirnonment but it will be skipped in the odyssey_fork CI run.
        eprintln!("Test skipped until the new contracts are deployed.");
        return Ok(());
    } else {
        run_e2e_prep(&build_txs).await?;
    }
    Ok(())
}

/// Executes all transactions from the test case by using the first tx context to upgrade the
/// account.
pub async fn run_e2e_upgraded<'a, F>(build_txs: &F) -> Result<()>
where
    F: Fn(&Environment) -> Vec<TxContext<'a>>,
{
    let mut env = Environment::setup_with_upgraded().await?;
    let txs = build_txs(&env);

    let mut first_tx_calls = vec![];
    for (tx_num, mut tx) in txs.into_iter().enumerate() {
        if tx_num == 0 {
            // Since upgrade account cannot bundle a list of `Call`, it returns them so they can
            // be bundled for the following transaction.
            first_tx_calls = tx.upgrade_account(&env, tx_num).await?;
        } else {
            tx.calls.splice(0..0, first_tx_calls.drain(..));
            process_tx(tx_num, tx, &env).await?;
        }
    }

    Ok(())
}

/// Executes all transactions from the test case by using the first tx context to create a
/// PREPAccount.
pub async fn run_e2e_prep<'a, F>(build_txs: &F) -> Result<()>
where
    F: Fn(&Environment) -> Vec<TxContext<'a>>,
{
    let mut env = Environment::setup_with_prep().await?;
    let txs = build_txs(&env);
    for (tx_num, mut tx) in txs.into_iter().enumerate() {
        if tx_num == 0 {
            tx.prep_account(&mut env, tx_num).await?;
        } else {
            process_tx(tx_num, tx, &env).await?;
        }
    }

    Ok(())
}

/// Processes a single transaction, returning error on a unexpected failure.
///
/// The process follows these steps:
/// 1. Obtains a signed quote and UserOp signature from [`prepare_calls`].
/// 2. Submits and verifies execution with [`send_prepared_calls`].
///    - Sends the prepared calls and signature to the relay
///    - Handles expected send failures
///    - Retrieves and checks transaction receipt
///    - Verifies transaction status matches expectations
///    - Confirms UserOp success by checking nonce invalidation
async fn process_tx(tx_num: usize, tx: TxContext<'_>, env: &Environment) -> Result<()> {
    let signer = tx.key.expect("should have key");

    let Some((signature, quote)) = prepare_calls(tx_num, &tx, signer, env).await? else {
        // We had an expected failure so we should exit.
        return Ok(());
    };

    let op_nonce = quote.ty().op.nonce;

    // Submit signed call
    let bundle = send_prepared_calls(env, signer, signature, quote).await;

    check_bundle(bundle, &tx, tx_num, None, op_nonce, env).await
}

/// Checks that the submitted bundle has had the expected test outcome.
async fn check_bundle(
    tx_hash: eyre::Result<B256>,
    tx: &TxContext<'_>,
    tx_num: usize,
    authorization: Option<SignedAuthorization>,
    op_nonce: U256,
    env: &Environment,
) -> Result<(), eyre::Error> {
    match tx_hash {
        Ok(tx_hash) => {
            if tx.expected.failed_send() {
                return Err(
                    eyre::eyre!("Send action {tx_num} passed when it should have failed.",),
                );
            }

            let receipt = PendingTransactionBuilder::new(env.provider.root().clone(), tx_hash)
                .get_receipt()
                .await
                .wrap_err("Failed to get receipt")?;

            if receipt.status() {
                if tx.expected.reverted_tx() {
                    return Err(eyre::eyre!(
                        "Transaction {tx_num} passed when it should have reverted.",
                    ));
                }
            } else if !tx.expected.reverted_tx() {
                return Err(eyre::eyre!("Transaction {tx_num} failed: {receipt:#?}"));
            }

            if let Some(auth) = authorization {
                if env.provider.get_code_at(env.eoa.address()).await?
                    != [&EIP7702_DELEGATION_DESIGNATOR[..], env.delegation.as_slice()].concat()
                {
                    return Err(eyre::eyre!("Transaction {tx_num} failed to delegate"));
                }
            }

            // UserOp has succeeded if the nonce has been invalidated.
            let (seq, err) = Entry::new(env.entrypoint, env.provider.clone())
                .nonce_status(env.eoa.address(), op_nonce)
                .await?;
            let nonce_invalidated = seq > (U256::from(op_nonce >> 192).to());
            let op_success = err == ENTRYPOINT_NO_ERROR;
            if nonce_invalidated && op_success {
                if tx.expected.failed_user_op() {
                    return Err(eyre::eyre!("UserOp {tx_num} passed when it should have failed."));
                }
            } else if !tx.expected.failed_user_op() {
                return Err(eyre::eyre!(
                    "Transaction succeeded but UserOp failed for transaction {tx_num}",
                ));
            }
        }
        Err(err) => {
            if tx.expected.failed_send() {
                return Ok(());
            }
            return Err(eyre::eyre!("Send error for transaction {tx_num}: {err}"));
        }
    };
    Ok(())
}

/// Obtains a [`SignedQuote`] from the relay by calling `wallet_prepare_calls` and signs the
/// `UserOp`
pub async fn prepare_calls(
    tx_num: usize,
    tx: &TxContext<'_>,
    signer: &KeyWith712Signer,
    env: &Environment,
) -> eyre::Result<Option<(Bytes, SignedQuote)>> {
    let response = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            from: env.eoa.address(),
            calls: tx.calls.clone(),
            chain_id: env.chain_id,
            capabilities: PrepareCallsCapabilities {
                authorize_keys: Some(tx.authorization_keys.clone()).filter(|keys| !keys.is_empty()),
                revoke_keys: None,
                meta: Meta {
                    fee_token: env.erc20,
                    key_hash: signer.key_hash(),
                    nonce: U256::from(tx_num),
                },
            },
        })
        .await;

    if response.is_err() {
        if tx.expected.failed_estimate() {
            return Ok(None);
        } else {
            return Err(eyre::eyre!("Fee estimation error for tx {tx_num}: {response:?}"));
        }
    }

    let PrepareCallsResponse { context, digest, .. } = response?;
    let signature = Signature {
        innerSignature: signer.sign_payload_hash(digest).await.wrap_err("Signing failed")?,
        keyHash: signer.key_hash(),
        prehash: false,
    }
    .abi_encode_packed()
    .into();

    Ok(Some((signature, context)))
}

/// Sends quote and UserOp signature to be broadcasted.
pub async fn send_prepared_calls(
    env: &Environment,
    signer: &KeyWith712Signer,
    signature: Bytes,
    quote: SignedQuote,
) -> eyre::Result<TxHash> {
    let response = env
        .relay_endpoint
        .send_prepared_calls(SendPreparedCallsParameters {
            context: quote,
            signature: SendPreparedCallsSignature {
                public_key: signer.publicKey.clone(),
                key_type: signer.keyType,
                value: signature,
            },
        })
        .await
        .map(|bundle| B256::from_str(&bundle.id).unwrap());

    response.map_err(Into::into)
}
