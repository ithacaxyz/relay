//! Relay end-to-end tests

mod cases;

mod common_calls;

mod config;
use config::{AccountConfig, PaymentConfig, TestConfig};

mod constants;
pub use constants::*;

mod environment;
use environment::*;

mod eoa;

mod types;
pub use types::*;

use alloy::{
    eips::eip7702::{SignedAuthorization, constants::EIP7702_DELEGATION_DESIGNATOR},
    primitives::{Address, B256, Bytes, TxHash, U256},
    providers::{PendingTransactionBuilder, Provider},
    sol_types::SolValue,
};
use eyre::{Context, Result};
use futures_util::future::try_join_all;
use itertools::iproduct;
use relay::{
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    types::{
        Delegation, ENTRYPOINT_NO_ERROR,
        EntryPoint::UserOpExecuted,
        KeyType, KeyWith712Signer, Signature, SignedQuote,
        rpc::{
            Meta, PrepareCallsCapabilities, PrepareCallsParameters, PrepareCallsResponse,
            SendPreparedCallsParameters, SendPreparedCallsSignature,
        },
    },
};
use std::iter;
use strum::IntoEnumIterator;

/// Runs all configurations (both PREP and upgraded account, in both ERC20 and native payment
/// methods).
pub async fn run_e2e<'a, F>(build_txs: F) -> Result<()>
where
    F: Fn(&Environment) -> Vec<TxContext<'a>> + Send + Sync + Copy,
{
    run_configs(build_txs, iproduct!(AccountConfig::iter(), PaymentConfig::iter())).await
}

/// Runs only the upgraded account configuration, in both ERC20 and native payment methods.
pub async fn run_e2e_upgraded<'a, F>(build_txs: F) -> Result<()>
where
    F: Fn(&Environment) -> Vec<TxContext<'a>> + Send + Sync + Copy,
{
    run_configs(build_txs, iproduct!(iter::once(AccountConfig::Upgraded), PaymentConfig::iter()))
        .await
}

/// Runs a set of test configurations.
pub async fn run_configs<'a, F>(
    build_txs: F,
    configs: impl Iterator<Item = impl Into<TestConfig>>,
) -> Result<()>
where
    F: Fn(&Environment) -> Vec<TxContext<'a>> + Send + Sync + Copy,
{
    let test_cases = configs.into_iter().map(async |config| {
        let config: TestConfig = config.into();
        config.run(build_txs).await.with_context(|| format!("Error in config {:?}", config))
    });

    try_join_all(test_cases).await?;

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
    _op_nonce: U256,
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

            if authorization.is_some()
                && env.provider.get_code_at(env.eoa.address()).await?
                    != [&EIP7702_DELEGATION_DESIGNATOR[..], env.delegation.as_slice()].concat()
            {
                return Err(eyre::eyre!("Transaction {tx_num} failed to delegate"));
            }

            // UserOp has succeeded if the nonce has been invalidated.
            let success = if let Some(event) = receipt.decoded_log::<UserOpExecuted>() {
                event.incremented && event.err == ENTRYPOINT_NO_ERROR
            } else {
                false
            };
            if success && tx.expected.failed_user_op() {
                return Err(eyre::eyre!("UserOp {tx_num} passed when it should have failed."));
            } else if !success && !tx.expected.failed_user_op() {
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
                authorize_keys: tx.authorization_keys.clone(),
                revoke_keys: Vec::new(),
                meta: Meta {
                    fee_token: env.fee_token,
                    key_hash: signer.key_hash(),
                    nonce: Some(U256::from(tx_num)),
                },
                pre_ops: Vec::new(),
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
        .map(|bundle| bundle.id);

    response.map_err(Into::into)
}
