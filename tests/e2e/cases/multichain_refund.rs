//! Multi-chain refund test case

use crate::e2e::{cases::multichain_usdt_transfer::MultichainTransferSetup, *};
use alloy::primitives::{Address, Bytes, U256};
use eyre::Result;
use relay::{
    storage::StorageApi,
    types::{IERC20, rpc::GetAssetsParameters},
};
use tokio::time::{Duration, sleep};

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

    // Check escrow balances on chains 1 & 2 before a refund can be processed
    for i in 0..2 {
        check_balances(&setup, i, wallet, U256::ZERO, setup.balances[i]).await?;
    }

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
    sleep(Duration::from_secs(1)).await;

    // Check that refunds have been processed on chains 1 & 2
    for i in 0..2 {
        check_balances(&setup, i, wallet, setup.balances[i], U256::ZERO).await?;
    }

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

/// Check wallet and escrow balances for a specific chain
async fn check_balances(
    setup: &MultichainTransferSetup,
    chain_index: usize,
    wallet: Address,
    expected_wallet_balance: U256,
    expected_escrow_balance: U256,
) -> Result<()> {
    // Check wallet balance
    let wallet_balance = IERC20::new(setup.env.erc20, setup.env.provider_for(chain_index))
        .balanceOf(wallet)
        .call()
        .await?;
    assert_eq!(
        wallet_balance,
        expected_wallet_balance,
        "Wallet balance on chain {}: expected {}, got {}",
        chain_index + 1,
        expected_wallet_balance,
        wallet_balance
    );

    // Check escrow balance
    let escrow_balance = IERC20::new(setup.env.erc20, setup.env.provider_for(chain_index))
        .balanceOf(setup.env.escrow)
        .call()
        .await?;
    assert_eq!(
        escrow_balance,
        expected_escrow_balance,
        "Escrow balance on chain {}: expected {}, got {}",
        chain_index + 1,
        expected_escrow_balance,
        escrow_balance
    );

    Ok(())
}
