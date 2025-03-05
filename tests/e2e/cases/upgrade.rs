//! Account upgrade related end-to-end test cases

use crate::e2e::environment::Environment;
use alloy::{
    primitives::{B256, U256},
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

async fn upgrade_account(env: &Environment, authorize_keys: Vec<AuthorizeKey>) -> eyre::Result<()> {
    let mut response = env
        .relay_endpoint
        .prepare_upgrade_account(PrepareUpgradeAccountParameters {
            address: env.eoa_signer.address(),
            chain_id: env.chain_id,
            capabilities: UpgradeAccountCapabilities {
                authorize_keys,
                delegation: env.delegation,
                fee_token: Some(env.erc20),
            },
        })
        .await?;

    // Sign UserOp digest
    let signature = env.eoa_signer.sign_hash(&response.digest).await?;

    // Sign 7702 delegation
    let authorization = alloy::eips::eip7702::Authorization {
        chain_id: U256::from(0),
        address: env.delegation,
        nonce: env.provider.get_transaction_count(env.eoa_signer.address()).await?,
    };
    let authorization_hash = authorization.signature_hash();
    let authorization = authorization.into_signed(
        env.eoa_signer.sign_hash(&authorization_hash).await.wrap_err("Auth signing failed")?,
    );

    // Upgrade account.
    let response = env
        .relay_endpoint
        .upgrade_account(UpgradeAccountParameters {
            context: response.context,
            signature,
            authorization,
        })
        .await?;

    // Check that transaction has been successful.
    let tx_hash = B256::from_str(&response.bundles[0].id)?;
    let receipt = PendingTransactionBuilder::new(env.provider.root().clone(), tx_hash)
        .get_receipt()
        .await
        .wrap_err("Failed to get receipt")?;

    assert!(receipt.status());

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn basic_upgrade() -> eyre::Result<()> {
    upgrade_account(&Environment::setup().await?, vec![]).await
}
