//! LayerZero settlement test case
//!
//! This test demonstrates cross-chain settlement using LayerZero:
//! - Sets up 3 local chains with LayerZero endpoints
//! - Executes a multichain transfer
//! - Verifies that settlement transactions are created and succeed

use crate::e2e::{
    cases::multichain_usdt_transfer::MultichainTransferSetup,
    layerzero::setup::LayerZeroEnvironment, *,
};
use alloy::{rpc::types::Filter, sol_types::SolEvent};
use eyre::Result;
use relay::{
    rpc::RelayApiClient,
    storage::{BundleStatus, StorageApi},
    types::{IEscrow, rpc::GetAssetsParameters},
};
use tokio::time::{Duration, sleep};

/// Tests successful cross-chain transfer with LayerZero settlement.
///
/// User has USDT on chains 1&2, wants to send to recipient on chain 3.
/// Funds are locked in escrow, settler provides liquidity on destination,
/// and LayerZero is used for cross-chain settlement attestation.
#[tokio::test(flavor = "multi_thread")]
async fn test_multichain_layerzero_settlement() -> Result<()> {
    // Set up the multichain transfer scenario with LayerZero
    let setup = MultichainTransferSetup::run_with_layer_zero().await?;

    // Start the LayerZero relayer for automatic message delivery
    let (relayer, _handles) = setup.env.start_layerzero_relayer().await?;

    let chain3_id = setup.env.chain_id_for(2);

    // Send prepared calls on chain 3
    let bundle_id =
        send_prepared_calls(&setup.env, &setup.key, setup.signature, setup.context).await?;
    let status = await_calls_status(&setup.env, bundle_id).await?;
    assert!(status.status.is_confirmed());

    // Target has receive our full transfer
    let assets = setup
        .env
        .relay_endpoint
        .get_assets(GetAssetsParameters::eoa(setup.target_recipient))
        .await?;
    assert!(
        assets.0.get(&chain3_id).unwrap().iter().any(|a| a.balance == setup.total_transfer_amount)
    );

    // Wait for settlement processing
    sleep(Duration::from_secs(1)).await;

    // Verify the bundle is no longer in pending bundles
    let pending_bundles = setup.env.relay_handle.storage.get_pending_bundles().await?;
    assert!(pending_bundles.is_empty(), "Bundle should be fully processed and no longer pending");

    // Verify LayerZero relayer picks up the message and can successfully relay it.
    assert_eq!(relayer.messages_seen(), 2, "Relayer should have seen exactly 2 messages"); // 2 lzSends
    assert_eq!(relayer.transactions_sent(), 2, "Relayer should have sent exactly 2 transactions");

    // Check that EscrowSettled events were emitted on the source chains
    for chain_idx in 0..2 {
        let logs = setup.env.providers[chain_idx]
            .get_logs(
                &Filter::new()
                    .address(setup.env.escrow)
                    .event_signature(IEscrow::EscrowSettled::SIGNATURE_HASH),
            )
            .await?;
        assert!(
            !logs.is_empty(),
            "Expected EscrowSettled event on chain {}",
            setup.env.chain_id_for(chain_idx)
        );
    }

    // Verify the bundle status is successful
    let finished_bundle =
        setup.env.relay_handle.storage.get_finished_interop_bundle(bundle_id).await?;

    let bundle_with_status = finished_bundle.expect("Bundle should be in finished_bundles table");
    assert_eq!(
        bundle_with_status.status,
        BundleStatus::Done,
        "Bundle should have Done status, but got: {:?}",
        bundle_with_status.status
    );

    Ok(())
}
