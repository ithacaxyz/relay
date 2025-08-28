use crate::e2e::{
    AuthKind, ExpectedOutcome, MockErc20, TxContext, await_calls_status,
    cases::{upgrade_account_eagerly, upgrade_account_lazily},
    environment::{Environment, EnvironmentConfig},
};
use alloy::{
    primitives::{Address, B256, Bytes, U64, U256, b256},
    providers::Provider,
    sol_types::SolCall,
    uint,
};
use relay::{
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    types::{
        Call, CallPermission, IERC20, KeyType, KeyWith712Signer,
        rpc::{
            AddFaucetFundsParameters, BundleId, GetAssetsParameters, GetAuthorizationParameters,
            GetKeysParameters, Meta, Permission, PrepareCallsCapabilities, PrepareCallsParameters,
            PrepareUpgradeAccountParameters, RequiredAsset, SendPreparedCallsParameters,
            UpgradeAccountCapabilities, UpgradeAccountParameters, UpgradeAccountSignatures,
            VerifySignatureParameters,
        },
    },
};
use std::str::FromStr;

const ADMIN_KEY: B256 = b256!("0x013c83ce5b08455e0505392b45f6d5effc7671e6f69108268ee4fedae1df72c8");
const SESSION_KEY: B256 =
    b256!("0xe1d7a91c93712db419ab647152bc1ae8739aca2f1bc8a6220d47fcf4a541a73c");

#[tokio::test]
async fn test_health() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    let response = env.relay_endpoint.health().await?;
    insta::assert_json_snapshot!(response, {
        ".status" => reduction_from_str::<String>("status"),
        ".version" => reduction_from_str::<String>("version"),
    });

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
    let response = env
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

    let mut value = serde_json::to_value(response)?;
    sort_json_keys(&mut value);
    // TODO: fee related redactions can be removed if we make the tip block of Anvil at the moment
    // of this assertion consistent across runs, right now it's either 15 or 16, and this changes
    // the EIP-1559 fee estimations.
    insta::assert_json_snapshot!(value, {
        ".capabilities.assetDiffs.*" => insta::sorted_redaction(),
        ".capabilities.feeTotals.*.value" => reduction_from_str::<f64>("value"),
        ".context.quote.hash" => reduction_from_str::<B256>("hash"),
        ".context.quote.quotes[].intent.encodedPreCalls[]" => reduction_from_str::<Bytes>("encodedPreCall"),
        ".context.quote.quotes[].intent.prePaymentAmount" => reduction_from_str::<U256>("prePaymentAmount"),
        ".context.quote.quotes[].intent.prePaymentMaxAmount" => reduction_from_str::<U256>("prePaymentMaxAmount"),
        ".context.quote.quotes[].intent.totalPaymentAmount" => reduction_from_str::<U256>("totalPaymentAmount"),
        ".context.quote.quotes[].intent.totalPaymentMaxAmount" => reduction_from_str::<U256>("totalPaymentMaxAmount"),
        ".context.quote.quotes[].nativeFeeEstimate.maxFeePerGas" => reduction_from_str::<U256>("maxFeePerGas"),
        ".context.quote.r" => reduction_from_str::<U256>("r"),
        ".context.quote.s" => reduction_from_str::<U256>("s"),
        ".context.quote.ttl" => insta::dynamic_redaction(|value, _path| {
            assert!(value.as_u64().unwrap() > std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs());
            "[ttl]"
        }),
        ".context.quote.v" => reduction_from_str::<U64>("v"),
        ".context.quote.yParity" => reduction_from_str::<U64>("yParity"),
        ".digest" => reduction_from_str::<B256>("digest"),
        ".typedData.message.encodedPreCalls[]" => reduction_from_str::<Bytes>("encodedPreCall"),
        ".typedData.message.prePaymentMaxAmount" => reduction_from_str::<U256>("prePaymentMaxAmount"),
        ".typedData.message.totalPaymentMaxAmount" => reduction_from_str::<U256>("totalPaymentMaxAmount"),
    });

    Ok(())
}

#[tokio::test]
async fn test_prepare_upgrade_account() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    let admin_key = KeyWith712Signer::mock_admin_with_key(KeyType::Secp256k1, ADMIN_KEY)?.unwrap();

    let response = env
        .relay_endpoint
        .prepare_upgrade_account(PrepareUpgradeAccountParameters {
            address: env.eoa.address(),
            delegation: env.delegation,
            chain_id: None,
            capabilities: UpgradeAccountCapabilities {
                authorize_keys: vec![admin_key.to_authorized()],
            },
        })
        .await?;

    // Nonces are random, so we need to redact them and the digest that depends on them.
    insta::assert_json_snapshot!(response, {
        ".digests.exec" => reduction_from_str::<B256>("digest"),
        ".context.preCall.nonce" => reduction_from_str::<B256>("nonce"),
        ".typedData.message.nonce" => reduction_from_str::<B256>("nonce"),
    });

    Ok(())
}

#[tokio::test]
async fn test_send_prepared_calls() -> eyre::Result<()> {
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
    let response = env
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

    let signature = key.sign_payload_hash(response.digest).await?;

    let response = env
        .relay_endpoint
        .send_prepared_calls(SendPreparedCallsParameters {
            capabilities: Default::default(),
            context: response.context,
            key: key.to_call_key(),
            signature,
        })
        .await?;

    insta::assert_json_snapshot!(response, {
        ".id" => reduction_from_str::<BundleId>("id"),
    });

    Ok(())
}

#[tokio::test]
async fn test_upgrade_account() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    let admin_key = KeyWith712Signer::mock_admin_with_key(KeyType::Secp256k1, ADMIN_KEY)?.unwrap();

    let response = env
        .relay_endpoint
        .prepare_upgrade_account(PrepareUpgradeAccountParameters {
            address: env.eoa.address(),
            delegation: env.delegation,
            chain_id: None,
            capabilities: UpgradeAccountCapabilities {
                authorize_keys: vec![admin_key.to_authorized()],
            },
        })
        .await?;

    // Sign Intent digest
    let precall_signature = env.eoa.sign_hash(&response.digests.exec).await?;

    // Sign 7702 delegation
    let nonce = env.provider().get_transaction_count(env.eoa.address()).await?;
    let authorization = AuthKind::Auth.sign(&env, nonce).await?;

    // Upgrade account.
    #[allow(clippy::let_unit_value)]
    let response = env
        .relay_endpoint
        .upgrade_account(UpgradeAccountParameters {
            context: response.context,
            signatures: UpgradeAccountSignatures {
                auth: authorization.signature()?,
                exec: precall_signature,
            },
        })
        .await?;

    insta::assert_json_snapshot!(response);

    Ok(())
}

#[tokio::test]
async fn test_get_authorization() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    let admin_key = KeyWith712Signer::mock_admin_with_key(KeyType::Secp256k1, ADMIN_KEY)?.unwrap();

    let response = env
        .relay_endpoint
        .prepare_upgrade_account(PrepareUpgradeAccountParameters {
            address: env.eoa.address(),
            delegation: env.delegation,
            chain_id: None,
            capabilities: UpgradeAccountCapabilities {
                authorize_keys: vec![admin_key.to_authorized()],
            },
        })
        .await?;

    // Sign Intent digest
    let precall_signature = env.eoa.sign_hash(&response.digests.exec).await?;

    // Sign 7702 delegation
    let nonce = env.provider().get_transaction_count(env.eoa.address()).await?;
    let authorization = AuthKind::Auth.sign(&env, nonce).await?;

    // Upgrade account.
    env.relay_endpoint
        .upgrade_account(UpgradeAccountParameters {
            context: response.context,
            signatures: UpgradeAccountSignatures {
                auth: authorization.signature()?,
                exec: precall_signature,
            },
        })
        .await?;

    // Get authorization
    let response = env
        .relay_endpoint
        .get_authorization(GetAuthorizationParameters { address: env.eoa.address() })
        .await?;

    insta::assert_json_snapshot!(response);

    Ok(())
}

#[tokio::test]
async fn test_get_calls_status() -> eyre::Result<()> {
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
    let response = env
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

    let signature = key.sign_payload_hash(response.digest).await?;

    let response = env
        .relay_endpoint
        .send_prepared_calls(SendPreparedCallsParameters {
            capabilities: Default::default(),
            context: response.context,
            key: key.to_call_key(),
            signature,
        })
        .await?;

    await_calls_status(&env, response.id).await?;

    let response = env.relay_endpoint.get_calls_status(response.id).await?;

    // TODO: these redactions are due to the same issue as in `test_prepare_calls`
    insta::assert_json_snapshot!(response, {
        ".id" => insta::dynamic_redaction(move |value, _path| {
            assert_eq!(BundleId::from_str(value.as_str().unwrap()), Ok(response.id));
            "[id]"
        }),
        ".receipts[].logs[].topics[]" => reduction_from_str::<B256>("topic"),
        ".receipts[].logs[].data" => reduction_from_str::<Bytes>("data"),
        ".receipts[].logs[].blockHash" => reduction_from_str::<B256>("blockHash"),
        ".receipts[].logs[].blockNumber" => reduction_from_str::<U64>("blockNumber"),
        ".receipts[].logs[].blockTimestamp" => reduction_from_str::<U64>("blockTimestamp"),
        ".receipts[].logs[].transactionHash" => reduction_from_str::<B256>("transactionHash"),
        ".receipts[].blockHash" => reduction_from_str::<B256>("blockHash"),
        ".receipts[].blockNumber" => reduction_from_str::<U64>("blockNumber"),
        ".receipts[].gasUsed" => reduction_from_str::<U64>("gasUsed"),
        ".receipts[].transactionHash" => reduction_from_str::<B256>("transactionHash"),
    });

    Ok(())
}

#[tokio::test]
async fn test_verify_signature() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    let key = KeyWith712Signer::mock_admin_with_key(KeyType::Secp256k1, ADMIN_KEY)?.unwrap();
    upgrade_account_lazily(&env, &[key.to_authorized()], AuthKind::Auth).await?;

    let digest = B256::ZERO;
    let signature = key.sign_payload_hash(digest).await?;

    let response = env
        .relay_endpoint
        .verify_signature(VerifySignatureParameters {
            address: env.eoa.address(),
            chain_id: env.chain_id(),
            digest,
            signature: signature.clone(),
        })
        .await?;

    insta::assert_json_snapshot!(response, {
        ".proof.initPreCall.nonce" => reduction_from_str::<U256>("nonce"),
        ".proof.initPreCall.signature" => reduction_from_str::<Bytes>("signature"),
    });

    Ok(())
}

#[tokio::test]
async fn test_add_faucet_funds() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    let response = env
        .relay_endpoint
        .add_faucet_funds(AddFaucetFundsParameters {
            token_address: env.fee_token,
            address: env.eoa.address(),
            chain_id: env.chain_id(),
            value: U256::ONE,
        })
        .await?;

    insta::assert_json_snapshot!(response, {
        ".transactionHash" => reduction_from_str::<B256>("transactionHash")
    });

    Ok(())
}

/// Creates a reduction that asserts value can be parsed using [`FromStr`], and replaces
/// the value with the provided name.
fn reduction_from_str<T: FromStr>(name: &str) -> insta::internals::Redaction {
    let name = name.to_string();
    insta::dynamic_redaction(move |value, _path| {
        assert!(T::from_str(value.as_str().unwrap()).is_ok());
        format!("[{}]", name)
    })
}

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
