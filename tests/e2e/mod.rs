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
    eips::eip7702::SignedAuthorization,
    primitives::{Address, B256, Bytes, U256, bytes},
    providers::{PendingTransactionBuilder, Provider},
    signers::Signer,
    sol_types::{SolCall, SolConstructor, SolEvent, SolStruct, SolValue},
    uint,
};
use eyre::{Context, OptionExt, Result};
use relay::{
    constants::EIP7702_DELEGATION_DESIGNATOR,
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    types::{
        Action, Delegation, ENTRYPOINT_NO_ERROR, Entry, Key, KeyType, PartialAction, PartialUserOp,
        Signature, SignedQuote, U40, UserOp, WebAuthnP256,
    },
};

/// Represents the parameters passed to `send_action`
pub struct ActionRequest {
    /// Action request.
    action: Action,
    /// Authorization item.
    authorization: Option<SignedAuthorization>,
    /// Signed quote.
    quote: SignedQuote,
}

/// Executes all transactions from the test case.
pub async fn run_e2e<F>(build_txs: F) -> Result<()>
where
    F: FnOnce(&Environment) -> Vec<TxContext>,
{
    let mut env = Environment::setup().await?;
    let txs = build_txs(&env);
    for (nonce, tx) in txs.into_iter().enumerate() {
        process_tx(nonce, tx, &env).await?;
    }
    Ok(())
}

/// Processes a single transaction, returning error on a unexpected failure.
///
/// The process follows these steps:
/// 1. Obtains a valid authorization (if required), signed quote and action request from
///    [`prepare_action_request`].
/// 2. Submits and verifies execution:
///    - Sends the action to the relay
///    - Handles expected send failures
///    - Retrieves and checks transaction receipt
///    - Verifies transaction status matches expectations
///    - Confirms UserOp success by checking nonce invalidation
async fn process_tx(tx_num: usize, tx: TxContext, env: &Environment) -> Result<()> {
    let Some(ActionRequest { action, authorization, quote }) =
        prepare_action_request(tx_num, &tx, env).await?
    else {
        // We had an expected failure so we should exit.
        return Ok(());
    };

    let eoa = action.op.eoa;
    let op_nonce = action.op.nonce;
    match env.relay_endpoint.send_action(action, quote, authorization.clone()).await {
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
                if env.provider.get_code_at(env.eoa_signer.address()).await?
                    != [&EIP7702_DELEGATION_DESIGNATOR[..], env.delegation.as_slice()].concat()
                {
                    return Err(eyre::eyre!("Transaction {tx_num} failed to delegate"));
                }
            }

            // UserOp has succeeded if the nonce has been invalidated.
            let (seq, err) = Entry::new(env.entrypoint, env.provider.clone())
                .nonce_status(eoa, op_nonce)
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
    }

    Ok(())
}

/// Obtains a [`ActionRequest`] if there's no expected test failure, otherwise `None`.
///
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
pub async fn prepare_action_request(
    tx_num: usize,
    tx: &TxContext,
    env: &Environment,
) -> eyre::Result<Option<ActionRequest>> {
    let execution_data: Bytes = tx.calls.abi_encode().into();
    let nonce = env.provider.get_transaction_count(env.eoa_signer.address()).await?;
    let authorization =
        if let Some(auth) = tx.auth.as_ref() { Some(auth.sign(env, nonce).await?) } else { None };

    let key_type = tx.key.as_ref().map(|k| k.keyType).unwrap_or(KeyType::Secp256k1);

    let quote = env
        .relay_endpoint
        .estimate_fee(
            PartialAction {
                op: PartialUserOp {
                    eoa: env.eoa_signer.address(),
                    executionData: execution_data.clone(),
                    nonce: U256::from(tx_num),
                },
                chain_id: env.chain_id,
            },
            env.erc20,
            authorization.as_ref().map(|auth| *auth.address()),
            key_type,
        )
        .await;

    if quote.is_err() {
        if tx.expected.failed_estimate() {
            return Ok(None);
        } else {
            return Err(eyre::eyre!("Fee estimation error for tx {tx_num}: {quote:?}"));
        }
    }

    let quote = quote?;
    let mut op = UserOp {
        eoa: env.eoa_signer.address(),
        executionData: execution_data.clone(),
        nonce: U256::from(tx_num),
        payer: Address::ZERO,
        paymentToken: env.erc20,
        paymentRecipient: Address::ZERO,
        paymentAmount: quote.ty().amount,
        paymentMaxAmount: quote.ty().amount,
        paymentPerGas: quote.ty().amount / U256::from(quote.ty().gas_estimate.op),
        combinedGas: U256::from(quote.ty().gas_estimate.op),
        signature: bytes!(""),
    };

    let entry = Entry::new(env.entrypoint, env.provider.root());
    let payload = op.as_eip712()?;
    let domain = entry.eip712_domain(op.is_multichain()).await.unwrap();

    op.signature = if tx.key.is_none() {
        env.eoa_signer
            .sign_payload_hash(payload.eip712_signing_hash(&domain))
            .await
            .wrap_err("Signing failed")?
    } else {
        let key = tx.key.as_ref().ok_or_eyre("Key should be specified")?;
        Signature {
            innerSignature: key
                .sign_typed_data(&payload, &domain)
                .await
                .wrap_err("Signing failed")?,
            keyHash: key.key_hash(),
            prehash: false,
        }
        .abi_encode_packed()
        .into()
    };

    Ok(Some(ActionRequest { action: Action { op, chain_id: env.chain_id }, authorization, quote }))
}
