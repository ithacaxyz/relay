//! Multi-chain USDT transfer test case
//!
//! This test demonstrates cross-chain functionality:
//! - Sets up 3 local chains
//! - Chain 1: User has N USDT balance
//! - Chain 2: User has N USDT balance
//! - Chain 3: User has 0 USDT balance (but has ETH for gas)
//! - Executes prepare_calls and send_prepared_calls on chain 3
//! - Attempts to transfer N+N USDT to address 0xbeef

use crate::e2e::{cases::upgrade_account_eagerly, *};
use alloy::primitives::{Address, U256, address};
use eyre::Result;
use relay::{
    config::TransactionServiceConfig,
    rpc::RelayApiClient,
    types::{
        IERC20, KeyType, KeyWith712Signer,
        rpc::{
            GetAssetsParameters, Meta, PrepareCallsCapabilities, PrepareCallsParameters,
            PrepareCallsResponse,
        },
    },
};

#[tokio::test(flavor = "multi_thread")]
async fn test_multichain_usdt_transfer() -> Result<()> {
    // Set up environment with 3 chains
    let num_chains = 3;
    let env = Environment::setup_with_config(EnvironmentConfig {
        num_chains,
        transaction_service_config: TransactionServiceConfig {
            num_signers: 1,
            ..Default::default()
        },
        ..Default::default()
    })
    .await?;
    let wallet = env.eoa.address();

    // Get chain ID for chain 3 (destination chain)
    let chain3_id = env.chain_id_for(2);

    // Target address for USDT transfers which
    let target_recipient = address!("000000000000000000000000000000000000beef");

    // Target recipient has no balance on chain 3
    let assets = env.relay_endpoint.get_assets(GetAssetsParameters::eoa(target_recipient)).await?;
    assert!(assets.0.get(&chain3_id).unwrap().iter().all(|a| a.balance == U256::ZERO));

    // Create a key for signing
    let key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();

    // Account ugprade deployed onchain.
    upgrade_account_eagerly(&env, &[key.to_authorized()], &key, AuthKind::Auth).await?;

    // Get initial balances on all chains
    let mut balances = Vec::with_capacity(num_chains);
    for i in 0..num_chains {
        let balance = IERC20::new(env.erc20, env.provider_for(i)).balanceOf(wallet).call().await?;
        balances.push(balance);
    }

    // Calculate the total balance
    let total_transfer_amount = balances[0] + balances[1] + balances[2];

    // Prepare the calls on chain 3 with required funds
    let prepare_result = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            calls: vec![common_calls::transfer(env.erc20, target_recipient, total_transfer_amount)],
            chain_id: chain3_id,
            from: Some(wallet),
            capabilities: PrepareCallsCapabilities {
                authorize_keys: vec![],
                revoke_keys: vec![],
                meta: Meta { fee_payer: None, fee_token: Address::ZERO, nonce: None },
                pre_calls: vec![],
                pre_call: false,
            },
            key: Some(key.to_call_key()),
            required_funds: vec![(env.erc20, total_transfer_amount)],
        })
        .await?;

    let PrepareCallsResponse { context, digest, .. } = prepare_result;

    // Sign the digest
    let signature = key.sign_payload_hash(digest).await?;

    // Send prepared calls on chain 3
    let bundle_id = send_prepared_calls(&env, &key, signature, context).await?;
    let status = await_calls_status(&env, bundle_id).await?;
    assert!(status.status.is_confirmed());

    // Target has receive our full transfer
    let assets = env.relay_endpoint.get_assets(GetAssetsParameters::eoa(target_recipient)).await?;
    assert!(assets.0.get(&chain3_id).unwrap().iter().any(|a| a.balance == total_transfer_amount));

    Ok(())
}
