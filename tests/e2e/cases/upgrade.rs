//! Account upgrade related end-to-end test cases

use crate::e2e::{AuthKind, environment::Environment};
use alloy::{
    eips::eip7702::SignedAuthorization,
    primitives::{Address, B256, TxHash, U256},
    providers::{PendingTransactionBuilder, Provider},
};
use eyre::WrapErr;
use relay::{
    rpc::RelayApiClient,
    types::{
        Entry, KeyType, KeyWith712Signer,
        rpc::{
            AuthorizeKey, PrepareCreateAccountCapabilities, PrepareUpgradeAccountParameters,
            UpgradeAccountCapabilities, UpgradeAccountParameters,
        },
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
                fee_token: env.erc20,
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
    let tx_hash = response.bundles[0].id;
    let receipt = PendingTransactionBuilder::new(env.provider.root().clone(), tx_hash)
        .get_receipt()
        .await
        .wrap_err("Failed to get receipt")?;

    assert!(receipt.status());

    Ok((tx_hash, authorization))
}

#[tokio::test(flavor = "multi_thread")]
async fn basic_upgrade() -> eyre::Result<()> {
    let key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    upgrade_account(
        &Environment::setup_with_upgraded().await?,
        &[key.to_authorized()],
        AuthKind::Auth,
    )
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_auth_quote_check() -> eyre::Result<()> {
    let key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    let mut env = Environment::setup_with_upgraded().await?;

    let mut response = env
        .relay_endpoint
        .prepare_upgrade_account(PrepareUpgradeAccountParameters {
            address: env.eoa.address(),
            chain_id: env.chain_id,
            capabilities: UpgradeAccountCapabilities {
                authorize_keys: vec![key.to_authorized()],
                delegation: env.delegation,
                fee_token: env.erc20,
            },
        })
        .await?;

    // Sign UserOp digest
    let signature = env.eoa.root_signer().sign_hash(&response.digest).await?;
    let nonce = env.provider.get_transaction_count(env.eoa.address()).await?;

    // Change delegation that we are signing so it's a mismatch.
    env.delegation = Address::random();
    let authorization = AuthKind::Auth.sign(&env, nonce).await?;

    // Upgrade account.
    let response = env
        .relay_endpoint
        .upgrade_account(UpgradeAccountParameters {
            context: response.context,
            signature,
            authorization: authorization.clone(),
        })
        .await;

    assert!(response.is_err());

    Ok(())
}
