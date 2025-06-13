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
use alloy::primitives::{Address, address};
use eyre::Result;
use relay::{
    rpc::RelayApiClient,
    types::{
        IERC20, KeyType, KeyWith712Signer,
        rpc::{Meta, PrepareCallsCapabilities, PrepareCallsParameters, PrepareCallsResponse},
    },
};

/// Target address for USDT transfers
const TARGET_ADDRESS: Address = address!("000000000000000000000000000000000000beef");

#[tokio::test(flavor = "multi_thread")]
async fn test_multichain_usdt_transfer() -> Result<()> {
    // Set up environment with 3 chains
    let num_chains = 3;
    let env = Environment::setup_multi_chain(num_chains).await?;
    let wallet = env.eoa.address();

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

    // Get chain ID for chain 3
    let chain3_id = env.chain_id_for(2);

    // Prepare the calls on chain 3
    let prepare_result = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            calls: vec![common_calls::transfer(env.erc20, TARGET_ADDRESS, total_transfer_amount)],
            chain_id: chain3_id,
            from: Some(wallet),
            capabilities: PrepareCallsCapabilities {
                authorize_keys: vec![],
                revoke_keys: vec![],
                meta: Meta { fee_payer: None, fee_token: env.fee_token, nonce: None },
                pre_calls: vec![],
                pre_call: false,
            },
            key: Some(key.to_call_key()),
        })
        .await?;

    let PrepareCallsResponse { context, digest, .. } = prepare_result;

    // Sign the digest
    let signature = key.sign_payload_hash(digest).await?;

    // Send prepared calls on chain 3
    let bundle_id = send_prepared_calls(&env, &key, signature, context).await?;
    let status = await_calls_status(&env, bundle_id).await?;
    assert!(status.status.is_confirmed());

    Ok(())
}
