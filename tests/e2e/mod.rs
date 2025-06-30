//! Relay end-to-end tests

mod cases;

pub mod common_calls;

mod config;
use config::{PaymentConfig, TestConfig};

mod constants;
pub use constants::*;

mod environment;
use environment::*;

mod layerzero;

mod eoa;

mod types;
pub use types::*;

use alloy::{
    network::Ethereum,
    primitives::{Address, B256, Bytes, U256},
    providers::{Provider, ext::AnvilApi},
    rpc::types::TransactionRequest,
};
use eyre::{Context, Result};
use futures_util::{future::try_join_all, try_join};
use relay::{
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    types::{
        IthacaAccount, KeyWith712Signer,
        rpc::{
            BundleId, CallsStatus, Meta, PrepareCallsCapabilities, PrepareCallsContext,
            PrepareCallsParameters, PrepareCallsResponse, SendPreparedCallsParameters,
        },
    },
};
use std::{iter, time::Duration};
use strum::IntoEnumIterator;

/// Runs all configurations (in both ERC20 and native payment methods).
pub async fn run_e2e<'a, F>(build_txs: F) -> Result<()>
where
    F: Fn(&Environment) -> Vec<TxContext<'a>> + Send + Sync + Copy,
{
    run_configs(build_txs, PaymentConfig::iter()).await
}

/// Runs tests with a ERC20 token as fee.
pub async fn run_e2e_erc20<'a, F>(build_txs: F) -> Result<()>
where
    F: Fn(&Environment) -> Vec<TxContext<'a>> + Send + Sync + Copy,
{
    run_configs(build_txs, iter::once(PaymentConfig::ERC20)).await
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
        config.run(build_txs).await.with_context(|| format!("Error in config {config:?}"))
    });

    try_join_all(test_cases).await?;

    Ok(())
}

/// Fetch the status of a bundle using `wallet_getCallsStatus`.
///
/// Internally will call `wallet_getCallsStatus` up to 10 times with a 1 second delay
/// between attempts.
async fn await_calls_status(
    env: &Environment,
    bundle_id: BundleId,
) -> Result<CallsStatus, eyre::Error> {
    let mut attempts = 0;
    loop {
        let status = env.relay_endpoint.get_calls_status(bundle_id).await.ok();

        if let Some(status) = status {
            if !status.status.is_pending() {
                return Ok(status);
            }
        }

        attempts += 1;
        if attempts > 10 {
            return Err(eyre::eyre!("bundle status not received within 10 attempts"));
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Obtains a [`SignedQuote`] from the relay by calling `wallet_prepare_calls` and signs the
/// `Intent`
pub async fn prepare_calls(
    tx_num: usize,
    tx: &TxContext<'_>,
    signer: &KeyWith712Signer,
    env: &Environment,
    pre_call: bool,
) -> eyre::Result<Option<(Bytes, PrepareCallsContext)>> {
    let pre_calls = build_pre_calls(env, &tx.pre_calls, tx_num).await?;

    // Deliberately omit the `from` address for the very first Intent precalls
    // to test the path where precalls are signed before the address is known.
    let from = (tx_num != 0 || !pre_call).then_some(env.eoa.address());

    let response = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            required_funds: vec![],
            from,
            calls: tx.calls.clone(),
            chain_id: env.chain_id(),
            capabilities: PrepareCallsCapabilities {
                authorize_keys: tx.authorization_keys(),
                revoke_keys: tx.revoke_keys(),
                meta: Meta {
                    fee_payer: None,
                    fee_token: tx.fee_token.unwrap_or(env.fee_token),
                    nonce: tx.nonce,
                },
                pre_calls,
                pre_call,
            },
            key: Some(signer.to_call_key()),
        })
        .await;

    if response.is_err() {
        if tx.expected.failed_estimate() {
            return Ok(None);
        } else {
            return Err(eyre::eyre!("Fee estimation error for tx {tx_num}: {response:?}"));
        }
    } else if tx.expected.failed_estimate() {
        return Err(eyre::eyre!("prepareCalls of tx {tx_num} passed when it should have failed."));
    }

    let PrepareCallsResponse { context, digest, .. } = response?;
    let signature = signer.sign_payload_hash(digest).await.wrap_err("Signing failed")?;

    Ok(Some((signature, context)))
}

/// Sends quote and Intent signature to be broadcasted.
pub async fn send_prepared_calls(
    env: &Environment,
    signer: &KeyWith712Signer,
    signature: Bytes,
    context: PrepareCallsContext,
) -> eyre::Result<BundleId> {
    let response = env
        .relay_endpoint
        .send_prepared_calls(SendPreparedCallsParameters {
            capabilities: Default::default(),
            context,
            key: signer.to_call_key(),
            signature,
        })
        .await
        .map(|bundle| bundle.id);

    response.map_err(Into::into)
}

/// Executes a transaction request as an impersonated account
pub async fn send_impersonated_tx<P: Provider + AnvilApi<Ethereum>>(
    provider: &P,
    tx_request: TransactionRequest,
    fund_amount: Option<U256>,
) -> Result<()> {
    // Extract from address
    let from = tx_request
        .from
        .ok_or_else(|| eyre::eyre!("Transaction request must have 'from' field set"))?;

    // Fund the account (if needed) and impersonate
    let fund_future = async {
        if let Some(amount) = fund_amount {
            return provider.anvil_set_balance(from, amount).await;
        }
        Ok(())
    };
    let impersonate_future = provider.anvil_impersonate_account(from);

    try_join!(fund_future, impersonate_future)?;

    // By using anvil_send_impersonated_transaction, we can use WalletProviders
    let tx_hash = provider.anvil_send_impersonated_transaction(tx_request).await?;

    // Get receipt and stop impersonation
    let receipt_future = provider.get_transaction_receipt(tx_hash);
    let stop_impersonate_future = provider.anvil_stop_impersonating_account(from);

    try_join!(receipt_future, stop_impersonate_future)?;

    Ok(())
}
