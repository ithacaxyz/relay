//! Account upgrade related end-to-end test cases

use crate::e2e::{AuthKind, environment::Environment};
use alloy::{
    eips::eip7702::SignedAuthorization,
    primitives::{B256, TxHash, U256},
    providers::{PendingTransactionBuilder, Provider},
};
use eyre::WrapErr;
use relay::{
    rpc::RelayApiClient,
    types::{
        CreateAccountCapabilities, Entry, PrepareUpgradeAccountParameters,
        UpgradeAccountCapabilities, UpgradeAccountParameters, capabilities::AuthorizeKey,
    },
};
use std::str::FromStr;

pub async fn upgrade_account(
    env: &Environment,
    authorize_keys: &[AuthorizeKey],
    auth: AuthKind,
) -> eyre::Result<(TxHash, SignedAuthorization)> {
    let mut response = env
        .relay_endpoint
        .prepare_upgrade_account(PrepareUpgradeAccountParameters {
            address: env.eoa.address(),
            chain_id: env.chain_id,
            capabilities: UpgradeAccountCapabilities {
                authorize_keys: authorize_keys.to_vec(),
                delegation: env.delegation,
                fee_token: Some(env.erc20),
            },
        })
        .await?;

    // Sign UserOp digest
    let signature = env.eoa.root_signer().sign_hash(&response.digest).await?;

    // Sign 7702 delegation
    let nonce = env.provider.get_transaction_count(env.eoa.address()).await?;
    let authorization = auth.sign(env, nonce).await?;

    // Upgrade account.
    let response = env
        .relay_endpoint
        .upgrade_account(UpgradeAccountParameters {
            context: response.context,
            signature,
            authorization: authorization.clone(),
        })
        .await?;

    // Check that transaction has been successful.
    let tx_hash = B256::from_str(&response.bundles[0].id)?;
    let receipt = PendingTransactionBuilder::new(env.provider.root().clone(), tx_hash)
        .get_receipt()
        .await
        .wrap_err("Failed to get receipt")?;

    assert!(receipt.status());

    Ok((tx_hash, authorization))
}

#[tokio::test(flavor = "multi_thread")]
async fn basic_upgrade() -> eyre::Result<()> {
    upgrade_account(&Environment::setup_with_upgraded().await?, &[], AuthKind::Auth).await?;
    Ok(())
}
