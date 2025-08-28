use crate::e2e::{
    AuthKind, ExpectedOutcome, MockErc20, TxContext,
    cases::{upgrade_account_eagerly, upgrade_account_lazily},
    environment::{Environment, EnvironmentConfig},
};
use alloy::{
    primitives::{Address, B256, U64, U256, b256},
    sol_types::SolCall,
    uint,
};
use relay::{
    rpc::RelayApiClient,
    types::{
        Call, CallPermission, IERC20, KeyType, KeyWith712Signer,
        rpc::{
            GetAssetsParameters, GetKeysParameters, Meta, Permission, PrepareCallsCapabilities,
            PrepareCallsParameters, RequiredAsset,
        },
    },
};

const ADMIN_KEY: B256 = b256!("0x013c83ce5b08455e0505392b45f6d5effc7671e6f69108268ee4fedae1df72c8");
const SESSION_KEY: B256 =
    b256!("0xe1d7a91c93712db419ab647152bc1ae8739aca2f1bc8a6220d47fcf4a541a73c");

#[tokio::test]
async fn test_health() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    let response = env.relay_endpoint.health().await?;
    insta::assert_json_snapshot!(response);

    Ok(())
}

#[tokio::test]
async fn test_get_capabilities() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    let mut response =
        env.relay_endpoint.get_capabilities(Some(vec![U64::from(env.chain_id())])).await?;

    for (_, caps) in response.0.iter_mut() {
        caps.contracts.legacy_orchestrators.sort();
        caps.contracts.legacy_delegations.sort();
        caps.fees.tokens.sort_by_key(|token| token.uid.clone());
    }

    insta::assert_json_snapshot!(response);

    Ok(())
}

#[tokio::test]
async fn test_get_keys() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    let admin_key = KeyWith712Signer::mock_admin_with_key(KeyType::Secp256k1, ADMIN_KEY)?.unwrap();
    let session_key = KeyWith712Signer::mock_session_with_key(KeyType::P256, SESSION_KEY)?
        .unwrap()
        .with_permissions(vec![Permission::Call(CallPermission {
            to: env.erc20,
            selector: MockErc20::transferCall::SELECTOR.into(),
        })]);

    upgrade_account_eagerly(&env, &[admin_key.to_authorized()], &admin_key, AuthKind::Auth).await?;

    // Add session key
    TxContext {
        authorization_keys: vec![&session_key],
        expected: ExpectedOutcome::Pass,
        key: Some(&admin_key),
        ..Default::default()
    }
    .process(0, &env)
    .await?;

    let response = env
        .relay_endpoint
        .get_keys(GetKeysParameters { address: env.eoa.address(), chain_ids: vec![] })
        .await?;
    insta::assert_json_snapshot!(response);

    Ok(())
}

#[tokio::test]
async fn test_get_assets() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    let mut response = env
        .relay_endpoint
        .get_assets(GetAssetsParameters { account: env.eoa.address(), ..Default::default() })
        .await?;

    for (_, assets) in response.0.iter_mut() {
        assets.sort_by_key(|asset| asset.address);
    }

    insta::assert_json_snapshot!(response);

    Ok(())
}

#[tokio::test]
async fn test_prepare_calls() -> eyre::Result<()> {
    let config =
        EnvironmentConfig { num_chains: 2, fee_recipient: Address::ZERO, ..Default::default() };
    let env = Environment::setup_with_config(config.clone()).await?;

    // Create a key for signing
    let key = KeyWith712Signer::mock_admin_with_key(KeyType::Secp256k1, ADMIN_KEY)?.unwrap();

    // Account upgrade deployed onchain.
    upgrade_account_lazily(&env, &[key.to_authorized()], AuthKind::Auth).await?;

    let balance =
        IERC20::new(env.erc20, env.provider_for(1)).balanceOf(env.eoa.address()).call().await?
            / uint!(2_U256);
    let mut response = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            calls: vec![Call::transfer(env.erc20, Address::ZERO, uint!(1_U256))],
            chain_id: env.chain_id_for(0),
            from: Some(env.eoa.address()),
            capabilities: PrepareCallsCapabilities {
                authorize_keys: Default::default(),
                meta: Meta { fee_token: env.erc20, fee_payer: None, nonce: Some(U256::ZERO) },
                pre_calls: Default::default(),
                pre_call: Default::default(),
                required_funds: vec![RequiredAsset::new(env.erc20, balance)],
                revoke_keys: Default::default(),
            },
            balance_overrides: Default::default(),
            state_overrides: Default::default(),
            key: Some(key.to_call_key()),
        })
        .await?;

    for asset_diff in response.capabilities.asset_diff.asset_diffs.values_mut() {
        asset_diff.0.sort_by_key(|(asset, _)| *asset);
    }

    let mut value = serde_json::to_value(response)?;
    sort_json_keys(&mut value);
    insta::assert_json_snapshot!(value);

    Ok(())
}

// async fn test_prepare_upgrade_account() -> eyre::Result<()> {
//     let env = Environment::setup().await?;

//     let response = env.relay_endpoint.prepare_upgrade_account().await?;

//     insta::assert_json_snapshot!(response);

//     Ok(())
// }

// async fn test_send_prepared_calls() -> eyre::Result<()> {
//     let env = Environment::setup().await?;

//     let response = env.relay_endpoint.send_prepared_calls().await?;

//     insta::assert_json_snapshot!(response);

//     Ok(())
// }

// async fn test_upgrade_account() -> eyre::Result<()> {
//     let env = Environment::setup().await?;

//     let response = env.relay_endpoint.upgrade_account().await?;

//     insta::assert_json_snapshot!(response);

//     Ok(())
// }

// async fn test_get_authorization() -> eyre::Result<()> {
//     let env = Environment::setup().await?;

//     let response = env.relay_endpoint.get_authorization().await?;

//     insta::assert_json_snapshot!(response);

//     Ok(())
// }

// async fn test_get_calls_status() -> eyre::Result<()> {
//     let env = Environment::setup().await?;

//     let response = env.relay_endpoint.get_calls_status().await?;

//     insta::assert_json_snapshot!(response);

//     Ok(())
// }

// async fn test_verify_signature() -> eyre::Result<()> {
//     let env = Environment::setup().await?;

//     let response = env.relay_endpoint.verify_signature().await?;

//     insta::assert_json_snapshot!(response);

//     Ok(())
// }

// async fn test_add_faucet_funds() -> eyre::Result<()> {
//     let env = Environment::setup().await?;

//     let response = env.relay_endpoint.add_faucet_funds().await?;

//     insta::assert_json_snapshot!(response);

//     Ok(())
// }

fn sort_json_keys(v: &mut serde_json::Value) {
    use serde_json::Value;
    match v {
        Value::Object(map) => {
            map.sort_keys();
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                sort_json_keys(v);
            }
        }
        _ => {}
    }
}
