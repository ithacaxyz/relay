//! Multi-chain refund test case

use crate::e2e::{cases::multichain_usdt_transfer::MultichainTransferSetup, *};
use alloy::{
    primitives::{Address, Bytes, U256},
    sol_types::{SolCall, SolValue},
};
use eyre::Result;
use relay::{
    storage::StorageApi,
    types::{Call, IERC20, IEscrow, rpc::GetAssetsParameters},
};
use tokio::time::{Duration, sleep};

/// Tests automatic refund mechanism when destination chain fails.
///
/// Transfer initiated but destination chain (3) stops processing. After 2s timeout,
/// funds locked in escrow on chains 1&2 are automatically refunded to user.
#[tokio::test(flavor = "multi_thread")]
async fn test_multichain_refund() -> Result<()> {
    // Set up the multichain transfer scenario with custom 2-second refund threshold
    let setup = MultichainTransferSetup::run_with_refund_threshold(2).await?;
    let wallet = setup.env.eoa.address();
    let chain3_id = setup.env.chain_id_for(2);

    // Disable mining on destination chain
    setup.env.disable_mining_on_chain(2).await;

    // Send prepared calls on chain 3
    let bundle_id =
        send_prepared_calls(&setup.env, &setup.key, setup.signature.clone(), setup.context.clone())
            .await?;

    // Wait for source/origin transactions to be processed
    sleep(Duration::from_secs(1)).await;

    let initial_total_balance: U256 = setup.balances.iter().sum();

    // Extract actual escrow amounts from the intent execution data
    let quotes = setup.context.quote().expect("should have quotes");
    let mut transfers_from_other_chains = U256::ZERO;

    // Decode escrow amounts from input intents (chains 0 and 1)
    for i in 0..2 {
        let intent = &quotes.ty().quotes[i].intent;
        let execution_data = intent.execution_data();

        // Decode the Vec<Call> from execution data
        let calls: Vec<Call> =
            Vec::<Call>::abi_decode(execution_data).expect("Failed to decode calls");

        // The escrow call is always the last call
        if let Some(last_call) = calls.last() {
            // Decode the escrow call to get the actual escrow amount
            if let Ok(escrow_call) = IEscrow::escrowCall::abi_decode(&last_call.data) {
                for escrow in escrow_call._escrows {
                    transfers_from_other_chains += escrow.escrowAmount;
                }
            }
        }
    }

    // We deduct the fees for the output intent since it won't be executed.
    let fees = setup.fees.iter().sum::<U256>() - setup.fees[2];

    // Check escrow and account balances.
    //
    // The total account balance across all chains should be the initial balance, minus transfers we
    // had to do from other chains, and any fees. The escrow should contain all the transfers
    // from other chains.
    check_balances(
        &setup,
        wallet,
        initial_total_balance - transfers_from_other_chains - fees,
        transfers_from_other_chains,
    )
    .await?;

    // Force failure on the destination chain transaction and mine the block
    setup.env.provider_for(2).anvil_set_code(setup.env.orchestrator, Bytes::default()).await?;
    setup.env.mine_block_on_chain(2).await;

    // Bundle should have failed
    let status = await_calls_status(&setup.env, bundle_id).await?;
    assert!(
        status.status.is_final() && !status.status.is_confirmed(),
        "Expected bundle to fail but got: {:?}",
        status.status
    );

    // Wait for refund processing to have been triggered
    sleep(Duration::from_secs(2)).await;

    // Check that refunds have been processed.
    //
    // In this state, the escrows should have no balance, and the account should have the initial
    // total balance, minus any fees incurred from escrowing.
    check_balances(&setup, wallet, initial_total_balance - fees, U256::ZERO).await?;

    // Verify target never received the funds on chain 3
    let assets = setup
        .env
        .relay_endpoint
        .get_assets(GetAssetsParameters::eoa(setup.target_recipient))
        .await?;
    assert!(
        assets.0.get(&chain3_id).unwrap().iter().all(|a| a.balance == U256::ZERO),
        "Target recipient should have zero balance on chain 3 after failed transaction"
    );

    // Verify pending_refund table is empty
    // Use a far future timestamp to get all pending refunds
    let future_time = chrono::Utc::now() + chrono::Duration::days(365);
    let pending_refunds =
        setup.env.relay_handle.storage.get_pending_refunds_ready(future_time).await?;
    assert!(pending_refunds.is_empty());

    // Verify the bundle is no longer in pending bundles
    let pending_bundles = setup.env.relay_handle.storage.get_pending_bundles().await?;
    assert!(pending_bundles.is_empty());

    Ok(())
}

async fn check_balances(
    setup: &MultichainTransferSetup,
    wallet: Address,
    expected_wallet_balance: U256,
    expected_escrow_balance: U256,
) -> Result<()> {
    let (wallet_balance, escrow_balance) = fetch_balances(setup, wallet).await?;

    assert_eq!(
        escrow_balance, expected_escrow_balance,
        "Escrow balance: expected {expected_escrow_balance}, got {escrow_balance}",
    );
    assert!(
        wallet_balance >= expected_wallet_balance,
        "Wallet balance: expected at least {expected_wallet_balance}, got {wallet_balance}",
    );

    Ok(())
}

/// Fetches balances for all chains and sums them up.
///
/// The return value is the total account balance across all chains, and then the total escrow
/// balance across all chains.
async fn fetch_balances(setup: &MultichainTransferSetup, wallet: Address) -> Result<(U256, U256)> {
    let mut wallet_balance = U256::ZERO;
    let mut escrow_balance = U256::ZERO;
    for chain_index in 0..3 {
        let chain_wallet_balance =
            IERC20::new(setup.env.erc20, setup.env.provider_for(chain_index))
                .balanceOf(wallet)
                .call()
                .await?;
        wallet_balance += chain_wallet_balance;

        let chain_escrow_balance =
            IERC20::new(setup.env.erc20, setup.env.provider_for(chain_index))
                .balanceOf(setup.env.escrow)
                .call()
                .await?;
        escrow_balance += chain_escrow_balance;

        // debug for if the test fails
        eprintln!(
            "balance on chain {chain_index}: account {chain_wallet_balance}, escrow: {chain_escrow_balance}"
        );
    }

    Ok((wallet_balance, escrow_balance))
}
