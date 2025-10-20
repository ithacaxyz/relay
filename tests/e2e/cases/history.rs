use crate::e2e::{
    environment::mint_erc20s,
    eoa::{MockAccount, MockAccountBuilder},
    *,
};
use alloy::primitives::{Address, U256};
use chrono::Utc;
use eyre::Result;
use relay::{
    rpc::{RelayApiClient, adjust_balance_for_decimals},
    storage::StorageApi,
    types::{
        Call, DiffDirection, HistoricalPrice, IERC20,
        rpc::{BundleId, CallHistoryEntry, GetCallsHistoryParameters, SortDirection},
    },
};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread")]
async fn test_multichain_calls_history_mixed_bundles() -> Result<()> {
    let env = Environment::setup_multi_chain(2).await?;

    // Create fresh account without ERC20 minting (includes initialization bundle)
    let account = MockAccountBuilder::new().no_erc20_mint().build(&env).await?;

    // Manually mint ERC20 on chain0 and chain1
    mint_erc20s(&[env.erc20], &[account.address], env.provider_for(0)).await?;
    mint_erc20s(&[env.erc20], &[account.address], env.provider_for(1)).await?;

    // Bundle 1: Single-chain on chain0
    let bundle1 = send_bundle(&env, &account, 0, U256::from(1), env.erc20).await?;

    // Sleep to ensure different timestamps for price testing
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Bundle 2: Single-chain on chain1
    let bundle2 = send_bundle(&env, &account, 1, U256::from(1), env.erc20).await?;

    // Sleep to ensure different timestamps for price testing
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Bundle 3: Interop - move more funds than available on chain1
    let bundle3 = {
        // Get decimals for both chains
        let decimals_0 = IERC20::new(env.erc20, env.provider_for(0)).decimals().call().await?;
        let decimals_1 = IERC20::new(env.erc20, env.provider_for(1)).decimals().call().await?;

        // Get balances on both chains
        let balance_chain0 =
            IERC20::new(env.erc20, env.provider_for(0)).balanceOf(account.address).call().await?;
        let balance_chain1 =
            IERC20::new(env.erc20, env.provider_for(1)).balanceOf(account.address).call().await?;

        // Adjust balance from chain0 to chain1 decimals
        let balance_chain0_adjusted =
            adjust_balance_for_decimals(balance_chain0, decimals_0, decimals_1);

        // Try to send on chain1: chain1_balance + half of chain0_balance (requires cross-chain)
        let amount_to_send = balance_chain1 + (balance_chain0_adjusted / U256::from(2));

        send_bundle(&env, &account, 1, amount_to_send, env.erc20).await?
    };

    populate_historical_prices(&env, &[bundle1, bundle2, bundle3]).await?;

    // Test 1: Fetch all history (ascending order)
    let history = get_history(&env, account.address, None, 10, SortDirection::Asc).await?;
    assert_asset_diffs_populated(&history);
    assert_eq!(history.len(), 4, "Expected 4 bundles in history");

    let bundle_ids: Vec<_> = history.iter().map(|e| e.id).collect();
    assert!(bundle_ids.contains(&bundle1));
    assert!(bundle_ids.contains(&bundle2));
    assert!(bundle_ids.contains(&bundle3));

    // Verify the first entry (initialization) is not one of our sent bundles
    assert_ne!(history[0].id, bundle1, "Init bundle should not be bundle1");
    assert_ne!(history[0].id, bundle2, "Init bundle should not be bundle2");
    assert_ne!(history[0].id, bundle3, "Init bundle should not be bundle3");

    // Verify bundle3 (interop) has quotes from both src and dst transactions
    let bundle3_entry = history.iter().find(|e| e.id == bundle3).expect("bundle3 should exist");
    assert_eq!(
        bundle3_entry.capabilities.quotes.len(),
        2,
        "Interop bundle should have 2 quotes (1 from src_txs, 1 from dst_txs)"
    );

    // Test 2: Fetch history in descending order
    let history_desc = get_history(&env, account.address, None, 10, SortDirection::Desc).await?;
    assert_asset_diffs_populated(&history);

    assert_eq!(history_desc.len(), 4);
    // Verify it's in reverse order
    assert_eq!(history_desc[0].id, bundle3, "Most recent should be bundle3");
    assert_eq!(history_desc[3].id, history[0].id, "Oldest should match first in asc");

    // Test 3: Limit to 2 bundles
    let history_limited = get_history(&env, account.address, None, 2, SortDirection::Asc).await?;
    assert_asset_diffs_populated(&history);

    assert_eq!(history_limited.len(), 2);
    assert_eq!(history_limited[0].id, history[0].id);
    assert_eq!(history_limited[1].id, history[1].id);

    // Test 4: Use index to paginate (skip first 2, get next 2)
    let history_paginated =
        get_history(&env, account.address, Some(2), 2, SortDirection::Asc).await?;
    assert_asset_diffs_populated(&history);

    assert_eq!(history_paginated.len(), 2);
    assert_eq!(history_paginated[0].id, history[2].id);
    assert_eq!(history_paginated[1].id, history[3].id);

    // Test 5: Index beyond available items
    let history_beyond =
        get_history(&env, account.address, Some(10), 10, SortDirection::Asc).await?;
    assert_eq!(history_beyond.len(), 0);

    // Test 6: Verify timestamps are increasing (ascending order)
    for i in 0..history.len() - 1 {
        assert!(
            history[i].timestamp <= history[i + 1].timestamp,
            "Timestamps should be in ascending order"
        );
    }

    Ok(())
}

async fn send_bundle(
    env: &Environment,
    account: &MockAccount,
    chain_idx: usize,
    amount: U256,
    fee_token: Address,
) -> Result<BundleId> {
    let response = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            calls: vec![Call::transfer(env.erc20, Address::random(), amount)],
            chain_id: env.chain_id_for(chain_idx),
            from: Some(account.address),
            capabilities: PrepareCallsCapabilities {
                meta: Meta { fee_token: Some(fee_token), ..Default::default() },
                ..Default::default()
            },
            key: Some(account.key.to_call_key()),
            ..Default::default()
        })
        .await?;

    let is_multichain = response.context.quote().unwrap().ty().multi_chain_root.is_some();
    let signature = account.key.sign_payload_hash(response.digest).await?;
    let bundle_id = send_prepared_calls(env, &account.key, signature, response.context).await?;

    let status = await_calls_status(env, bundle_id).await?;
    assert!(status.status.is_confirmed());
    if is_multichain {
        assert!(status.capabilities.unwrap().interop_status.unwrap().is_done());
    }

    Ok(bundle_id)
}

/// Helper to fetch call history with given parameters
async fn get_history(
    env: &Environment,
    address: Address,
    index: Option<u64>,
    limit: u64,
    sort: SortDirection,
) -> Result<Vec<CallHistoryEntry>> {
    env.relay_endpoint
        .get_calls_history(GetCallsHistoryParameters { address, index, limit, sort })
        .await
        .map_err(Into::into)
}

/// Helper to verify that asset diffs and fee totals are populated
fn assert_asset_diffs_populated(entries: &[CallHistoryEntry]) {
    for entry in entries {
        let asset_diff = &entry.capabilities.asset_diff;

        assert!(!asset_diff.fee_totals.is_empty());
        assert!(!asset_diff.asset_diffs.is_empty());

        for chain_diffs in asset_diff.asset_diffs.values() {
            for (_, diffs) in &chain_diffs.0 {
                for diff in diffs {
                    assert!(diff.fiat.is_some(),);
                }
            }
        }
    }
}

/// Test that verifies exact asset diff values match on-chain execution with the correct payer fee
/// removed (only the transfer amount should show up).
#[tokio::test(flavor = "multi_thread")]
async fn test_calls_history_exact_asset_diffs() -> Result<()> {
    let env = Environment::setup().await?;
    let account = MockAccountBuilder::new().build(&env).await?;
    let transfer_amount = U256::from(1000);
    let bundle_id = send_bundle(&env, &account, 0, transfer_amount, env.erc20).await?;
    populate_historical_prices(&env, &[bundle_id]).await?;

    let history = get_history(&env, account.address, None, 10, SortDirection::Asc).await?;
    let entry = history.iter().find(|e| e.id == bundle_id).unwrap();

    let quote = &entry.capabilities.quotes[0];
    let eoa_diffs = entry
        .capabilities
        .asset_diff
        .asset_diffs
        .get(&quote.chain_id)
        .unwrap()
        .0
        .iter()
        .find(|(addr, _)| addr == &account.address)
        .map(|(_, diffs)| diffs)
        .unwrap();

    let erc20_diff =
        eoa_diffs.iter().find(|d| d.address == Some(env.erc20)).expect("ERC20 diff should exist");

    assert_eq!(erc20_diff.value, transfer_amount,); // fee got removed correctly
    assert_eq!(erc20_diff.direction, DiffDirection::Outgoing,);
    assert!(!erc20_diff.recipients.is_empty(),);
    assert!(erc20_diff.fiat.is_some());

    let fee_total_price = entry
        .capabilities
        .asset_diff
        .fee_totals
        .get(&quote.chain_id)
        .expect("Fee total should exist for chain");

    assert!(fee_total_price.value > 0.0,);
    assert_eq!(fee_total_price.currency, "usd",);

    Ok(())
}

/// Helper to populate historical USD prices for bundles
async fn populate_historical_prices(env: &Environment, _bundle_ids: &[BundleId]) -> Result<()> {
    let now = Utc::now().timestamp() as u64;
    let (erc20_asset_uid, _) =
        env.relay_handle.chains.asset(env.chain_id(), env.erc20).expect("erc20 asset should exist");

    let mut prices = Vec::new();

    let (native_asset_uid, _) = env
        .relay_handle
        .chains
        .asset(env.chain_id(), Address::ZERO)
        .expect("native asset should exist");

    for asset_uid in [erc20_asset_uid, native_asset_uid] {
        prices.push(HistoricalPrice {
            asset_uid: asset_uid.clone(),
            timestamp: now - 60,
            usd_price: 1.0,
        });
        prices.push(HistoricalPrice {
            asset_uid: asset_uid.clone(),
            timestamp: now,
            usd_price: 2.0,
        });
        prices.push(HistoricalPrice {
            asset_uid: asset_uid.clone(),
            timestamp: now + 60,
            usd_price: 3.0,
        });
    }

    env.relay_handle.storage.store_historical_usd_prices(prices).await?;

    Ok(())
}
