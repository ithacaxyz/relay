//! Simulation test cases for prepare_calls with uncreated accounts

use crate::e2e::environment::Environment;
use alloy::primitives::{Address, U256};
use relay::{
    rpc::RelayApiClient,
    types::{
        Call,
        rpc::{Meta, PrepareCallsCapabilities, PrepareCallsParameters},
    },
};

/// Test that prepare_calls succeeds with an account that has not yet been created,
/// and that the response includes asset deficits.
#[tokio::test(flavor = "multi_thread")]
async fn test_simulate_without_created_account() -> eyre::Result<()> {
    let env = Environment::setup().await?;
    let transfer_amount = U256::from(100);
    let eoa = Address::random();

    for fee_token in [env.fee_token, env.erc20, Address::ZERO] {
        let params = PrepareCallsParameters {
            from: Some(eoa),
            calls: vec![Call::transfer(env.erc20, Address::random(), transfer_amount)],
            chain_id: env.chain_id(),
            capabilities: PrepareCallsCapabilities {
                meta: Meta { fee_payer: None, fee_token: Some(fee_token), nonce: None },
                authorize_keys: vec![],
                revoke_keys: vec![],
                pre_calls: vec![],
                pre_call: false,
                required_funds: vec![],
            },
            state_overrides: Default::default(),
            balance_overrides: Default::default(),
            key: None,
        };

        let response = env.relay_endpoint.prepare_calls(params).await?;
        let quote = &response.context.quote().as_ref().expect("Should have a quote").ty().quotes[0];
        assert!(!quote.fee_token_deficit.is_zero());

        let expected_erc20_amount = if env.erc20 == fee_token {
            transfer_amount + quote.fee_token_deficit
        } else {

            assert!(quote.asset_deficits.0.iter().any(
                |deficit| (deficit.address == Some(fee_token) || deficit.address == None) && deficit.deficit == quote.fee_token_deficit
            ));

            transfer_amount
        };

        assert!(quote.asset_deficits.0.iter().any(
            |deficit| deficit.address == Some(env.erc20) && deficit.deficit == expected_erc20_amount
        ));
    }

    Ok(())
}
