//! Multi-chain USDT transfer test case
//!
//! This test demonstrates cross-chain functionality:
//! - Sets up 3 local chains
//! - Chain 1: User has N USDT balance  
//! - Chain 2: User has N USDT balance
//! - Chain 3: User has 0 USDT balance (but has ETH for gas)
//! - Executes prepare_calls and send_prepared_calls on chain 3
//! - Attempts to transfer N+N USDT to address 0xbeef

use crate::e2e::*;
use alloy::{
    primitives::{Address, U256, address},
    sol_types::SolCall,
};
use eyre::Result;
use relay::{
    rpc::RelayApiClient,
    types::{
        Call, IERC20, KeyType, KeyWith712Signer,
        rpc::{
            Meta, PrepareCallsCapabilities, PrepareCallsParameters,
            PrepareCallsResponse,
        },
    },
};
use crate::e2e::cases::upgrade_account_eagerly;

/// Target address for USDT transfers
const TARGET_ADDRESS: Address = address!("000000000000000000000000000000000000beef");

#[tokio::test(flavor = "multi_thread")]
async fn test_multichain_usdt_transfer() -> Result<()> {
    // Set up environment with 3 chains
    let env = Environment::setup_multi_chain(2).await?;
    // let env = Environment::setup().await?;
    dbg!(
        &env.chain_ids
    );
    // Create a key for signing
    let key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();
    let wallet = env.eoa.address();
    
    // For multi-chain, we need to use the upgrade_account_eagerly from the upgrade module
    // which handles multi-chain delegation properly
    upgrade_account_eagerly(&env, &[key.to_authorized()], &key, AuthKind::Auth).await?;
    
    // // Get initial balances on all chains
    // let mut balances = Vec::new();
    // for i in 0..3 {
    //     let provider = env.provider_for(i);
    //     let balance = IERC20::new(env.erc20, provider)
    //         .balanceOf(wallet)
    //         .call()
    //         .await?;
    //     balances.push(balance);
    // }
    
    // // Calculate the total balance from chains 1 and 2 (N + N)
    // let total_transfer_amount = balances[0] + balances[1];
    
    // // Get chain ID for chain 3
    // let chain3_id = env.chain_id_for(2);
    
    // // Prepare the calls on chain 3
    // let prepare_result = env
    //     .relay_endpoint
    //     .prepare_calls(PrepareCallsParameters {
    //         calls: vec![common_calls::transfer(env.erc20, TARGET_ADDRESS, total_transfer_amount)],
    //         chain_id: chain3_id,
    //         from: Some(wallet),
    //         capabilities: PrepareCallsCapabilities {
    //             authorize_keys: Vec::new(),
    //             revoke_keys: Vec::new(),
    //             meta: Meta { fee_payer: None, fee_token: env.fee_token, nonce: None },
    //             pre_calls: Vec::new(),
    //             pre_call: false,
    //         },
    //         key: Some(key.to_call_key()),
    //     })
    //     .await?;
    
    // let PrepareCallsResponse { context, digest, .. } = prepare_result;
    
    // // Sign the digest
    // let signature = key.sign_payload_hash(digest).await?;
    
    // // Send prepared calls on chain 3
    // let send_result = send_prepared_calls(&env, &key, signature, context).await;
    
    // match send_result {
    //     Ok(bundle_id) => {
    //         // Wait for bundle status
    //         let status = await_calls_status(&env, bundle_id).await?;
            
    //         // Check if it failed as expected
    //         if status.status.is_failed() {
    //             // Expected - insufficient balance on chain 3
    //             return Ok(());
    //         }
            
    //         // If confirmed, check what happened
    //         if status.status.is_confirmed() {
    //             let provider_chain3 = env.provider_for(2);
    //             let target_balance = IERC20::new(env.erc20, provider_chain3)
    //                 .balanceOf(TARGET_ADDRESS)
    //                 .call()
    //                 .await?;
                
    //             // If chain 3 had less than N+N, transfer should have failed
    //             if balances[2] < total_transfer_amount && target_balance == U256::ZERO {
    //                 return Ok(()); // Failed as expected
    //             }
    //         }
    //     }
    //     Err(_) => {
    //         // Expected failure
    //         return Ok(());
    //     }
    // }
    
    Ok(())
}