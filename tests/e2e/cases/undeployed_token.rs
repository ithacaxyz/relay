//! Test for undeployed ERC20 tokens in asset diffs

use crate::e2e::{
    AuthKind, Environment, MockErc20, await_calls_status, cases::upgrade_account_eagerly,
    deploy_contract,
};
use alloy::{
    primitives::{Address, B256, U256},
    sol_types::SolCall,
};
use eyre::Result;
use relay::{
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    types::{
        Call, KeyType, KeyWith712Signer,
        rpc::{PrepareCallsParameters, SendPreparedCallsParameters},
    },
};

alloy::sol! {
    #[sol(rpc)]
    interface ERC1967Factory {
        function deployDeterministic(address implementation, address admin, bytes32 salt) external payable returns (address);
        function predictDeterministicAddress(bytes32 salt) external view returns (address);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_undeployed_token_in_asset_diffs() -> Result<()> {
    let env = Environment::setup().await?;
    let main_key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();

    upgrade_account_eagerly(&env, &[main_key.to_authorized()], &main_key, AuthKind::Auth).await?;

    let factory = deploy_contract(
        env.provider(),
        &Environment::contracts_path().join("ERC1967Factory.sol/ERC1967Factory.json"),
        None,
    )
    .await?;

    let salt = B256::ZERO;
    let token_address = ERC1967Factory::ERC1967FactoryInstance::new(factory, env.provider())
        .predictDeterministicAddress(salt)
        .call()
        .await?;

    let response = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            from: Some(env.eoa.address()),
            chain_id: env.chain_id(),
            key: Some(main_key.to_call_key()),
            calls: vec![
                Call {
                    to: factory,
                    value: U256::ZERO,
                    data: ERC1967Factory::deployDeterministicCall {
                        implementation: env.erc20,
                        admin: env.eoa.address(),
                        salt,
                    }
                    .abi_encode()
                    .into(),
                },
                Call {
                    to: token_address,
                    value: U256::ZERO,
                    data: MockErc20::mintCall { a: env.eoa.address(), val: U256::from(200) }
                        .abi_encode()
                        .into(),
                },
                Call::transfer(token_address, Address::ZERO, U256::from(100)),
            ],
            ..Default::default()
        })
        .await?;

    // Verify asset diffs
    let asset_diffs = &response.capabilities.asset_diff.asset_diffs;
    let chain_diffs = asset_diffs.get(&env.chain_id()).expect("Should have chain diffs");

    let eoa_diffs = &chain_diffs
        .0
        .iter()
        .find(|(addr, _)| addr == &env.eoa.address())
        .expect("Should have EOA diffs")
        .1;

    let token_diff = eoa_diffs
        .iter()
        .find(|diff| diff.address == Some(token_address))
        .expect("Should have diff for deployed token");

    assert!(token_diff.metadata.symbol.is_some());
    assert!(token_diff.metadata.name.is_some());
    assert!(token_diff.metadata.decimals.is_some());

    let send_response = env
        .relay_endpoint
        .send_prepared_calls(SendPreparedCallsParameters {
            context: response.context,
            signature: main_key.sign_payload_hash(response.digest).await?,
            key: Some(main_key.to_call_key()),
            capabilities: Default::default(),
        })
        .await?;

    let status = await_calls_status(&env, send_response.id).await?;
    assert!(status.status.is_confirmed());

    Ok(())
}
