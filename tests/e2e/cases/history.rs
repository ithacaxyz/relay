use crate::e2e::{
    environment::mint_erc20s,
    eoa::{MockAccount, MockAccountBuilder},
    *,
};
use alloy::primitives::{Address, U256};
use eyre::Result;
use relay::{
    rpc::{RelayApiClient, adjust_balance_for_decimals},
    types::{
        Call, IERC20,
        rpc::{BundleId, GetCallsHistoryParameters, SortDirection},
    },
};


#[tokio::test(flavor = "multi_thread")]
async fn test_calls_history_mixed_bundles() -> Result<()> {
    let env = Environment::setup_multi_chain(2).await?;

    // Create fresh account without ERC20 minting (includes initialization bundle)
    let account = MockAccountBuilder::new().no_erc20_mint().build(&env).await?;

    // Manually mint ERC20 on chain0 and chain1
    mint_erc20s(&[env.erc20], &[account.address], env.provider_for(0)).await?;
    mint_erc20s(&[env.erc20], &[account.address], env.provider_for(1)).await?;

    // Bundle 1: Single-chain on chain0
    let bundle1 = send_bundle(&env, &account, 0, U256::from(1)).await?;

    // Bundle 2: Single-chain on chain1
    let bundle2 = send_bundle(&env, &account, 1, U256::from(1)).await?;

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

        send_bundle(&env, &account, 1, amount_to_send).await?
    };

    // Fetch history
    let history = env
        .relay_endpoint
        .get_calls_history(GetCallsHistoryParameters {
            address: account.address,
            index: None,
            limit: 10,
            sort: SortDirection::Asc,
        })
        .await?;

    // Assert: 4 bundles total (1 initialization + 3 sent)
    assert_eq!(history.len(), 4, "Expected 4 bundles in history");

    // Verify bundle IDs are present
    let bundle_ids: Vec<_> = history.iter().map(|e| e.id).collect();
    assert!(bundle_ids.contains(&bundle1));
    assert!(bundle_ids.contains(&bundle2));
    assert!(bundle_ids.contains(&bundle3));

    Ok(())
}


async fn send_bundle(
    env: &Environment,
    account: &MockAccount,
    chain_idx: usize,
    amount: U256,
) -> Result<BundleId> {
    let response = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            calls: vec![Call::transfer(env.erc20, Address::random(), amount)],
            chain_id: env.chain_id_for(chain_idx),
            from: Some(account.address),
            capabilities: PrepareCallsCapabilities {
                meta: Meta { fee_token: Some(env.erc20), ..Default::default() },
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