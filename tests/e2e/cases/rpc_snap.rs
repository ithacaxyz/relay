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
    rpc::{AccountApiClient, RelayApiClient},
    signers::Eip712PayLoadSigner,
    storage::StorageApi,
    types::{
        Account, Call, CallPermission, IERC20, KeyType, KeyWith712Signer,
        rpc::{
            AddFaucetFundsParameters, BundleId, GetAssetsParameters, GetAuthorizationParameters,
            GetKeysParameters, GetOnrampContactInfoParameters, Meta, OnrampStatusParameters,
            Permission, PrepareCallsCapabilities, PrepareCallsParameters,
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
        ".quoteSigner" => reduction_from_str::<Address>("quoteSigner"),
    });

    Ok(())
}

#[tokio::test]
async fn test_get_capabilities() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    let mut response =
        env.relay_endpoint.get_capabilities(Some(vec![U64::from(env.chain_id())])).await?;

    for (_, caps) in response.0.iter_mut() {
        caps.contracts
            .legacy_orchestrators
            .sort_by(|a, b| a.orchestrator.address.cmp(&b.orchestrator.address));
        caps.contracts.legacy_delegations.sort_by(|a, b| a.address.cmp(&b.address));
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
                meta: Meta { fee_token: Some(env.erc20), fee_payer: None, nonce: Some(U256::ZERO) },
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

    let value = serde_json::to_value(response)?;
    // TODO: fee related redactions can be removed if we make the tip block of Anvil at the moment
    // of this assertion consistent across runs, right now it's either 15 or 16, and this changes
    // the EIP-1559 fee estimations.
    insta::assert_json_snapshot!(value, {
        ".capabilities.assetDiffs.*" => insta::sorted_redaction(),
        ".capabilities.feeTotals.*.value" => reduction_from_str::<f64>("value"),
        ".context.quote.hash" => reduction_from_str::<B256>("hash"),
        ".context.quote.quotes[].intent.combinedGas" => reduction_from_str::<U256>("combinedGas"),
        ".context.quote.quotes[].intent.encodedPreCalls[]" => reduction_from_str::<Bytes>("encodedPreCall"),
        ".context.quote.quotes[].intent.paymentAmount" => reduction_from_str::<U256>("paymentMaxAmount"),
        ".context.quote.quotes[].intent.paymentMaxAmount" => reduction_from_str::<U256>("paymentMaxAmount"),
        ".context.quote.quotes[].nativeFeeEstimate.maxFeePerGas" => reduction_from_str::<U256>("maxFeePerGas"),
        ".context.quote.quotes[].txGas" => reduction_from_str::<U256>("txGas"),
        ".context.quote.r" => reduction_from_str::<U256>("r"),
        ".context.quote.s" => reduction_from_str::<U256>("s"),
        ".context.quote.ttl" => insta::dynamic_redaction(move |value, _path| {
            assert!(value.as_u64().is_some());
            "[ttl]"
        }),
        ".context.quote.v" => reduction_from_str::<U64>("v"),
        ".context.quote.yParity" => reduction_from_str::<U64>("yParity"),
        ".digest" => reduction_from_str::<B256>("digest"),
        ".signature" => reduction_from_str::<Bytes>("signature"),
        ".typedData.message.combinedGas" => reduction_from_str::<U256>("combinedGas"),
        ".typedData.message.encodedPreCalls[]" => reduction_from_str::<Bytes>("encodedPreCall"),
        ".typedData.message.paymentMaxAmount" => reduction_from_str::<U256>("paymentMaxAmount"),
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
                meta: Meta { fee_token: Some(env.erc20), fee_payer: None, nonce: Some(U256::ZERO) },
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
            key: Some(key.to_call_key()),
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

    insta::assert_json_snapshot!(response, {
        ".data" => reduction_from_str::<Bytes>("data"),
    });

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
                meta: Meta { fee_token: Some(env.erc20), fee_payer: None, nonce: Some(U256::ZERO) },
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
            key: Some(key.to_call_key()),
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
    let signature = key
        .sign_payload_hash(Account::new(env.eoa.address(), env.provider()).digest_erc1271(digest))
        .await?;

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

#[tokio::test]
async fn test_onramp() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    // Test with verified email and phone
    let email = "test@example.com";
    let phone = "+1234567890";

    env.relay_handle.storage.add_unverified_email(env.eoa.address(), email, "token123").await?;
    env.relay_handle.storage.verify_email(env.eoa.address(), email, "token123").await?;
    env.relay_handle.storage.add_unverified_phone(env.eoa.address(), phone, "sid123").await?;
    env.relay_handle.storage.mark_phone_verified(env.eoa.address(), phone).await?;

    // Test onramp status
    let status_response = env
        .relay_endpoint
        .onramp_status(OnrampStatusParameters { address: env.eoa.address() })
        .await?;

    assert!(status_response.email.is_some(), "Email timestamp should be present");
    assert!(status_response.phone.is_some(), "Phone timestamp should be present");

    insta::assert_json_snapshot!("status_verified", status_response, {
        ".email" => "[email_timestamp]",
        ".phone" => "[phone_timestamp]",
    });

    // Test get contact info with invalid secret
    let result_invalid = env
        .relay_endpoint
        .get_onramp_contact_info(GetOnrampContactInfoParameters {
            address: env.eoa.address(),
            secret: "wrong_secret".to_string(),
        })
        .await;

    assert!(result_invalid.is_err(), "Should fail with invalid secret");

    // Test get contact info with valid secret
    let contact_response = env
        .relay_endpoint
        .get_onramp_contact_info(GetOnrampContactInfoParameters {
            address: env.eoa.address(),
            secret: "test_onramp_secret".to_string(),
        })
        .await?;

    assert_eq!(contact_response.email.as_deref(), Some(email), "Email should match");
    assert_eq!(contact_response.phone.as_deref(), Some(phone), "Phone should match");

    insta::assert_json_snapshot!("contact_info_verified", contact_response, {
        ".phoneVerifiedAt" => "[phone_timestamp]",
    });

    // Test with email - first unverified, then verified
    let email_only_addr = Address::random();
    let email_only = "emailonly@example.com";
    env.relay_handle.storage.add_unverified_email(email_only_addr, email_only, "token456").await?;

    // Test unverified state
    let status_unverified_email = env
        .relay_endpoint
        .onramp_status(OnrampStatusParameters { address: email_only_addr })
        .await?;

    assert!(
        status_unverified_email.email.is_some(),
        "Email timestamp (created_at) should be present for unverified email"
    );
    assert!(status_unverified_email.phone.is_none(), "Phone should be None");

    insta::assert_json_snapshot!("status_unverified_email", status_unverified_email, {
        ".email" => "[email_timestamp]",
    });

    let contact_unverified_email = env
        .relay_endpoint
        .get_onramp_contact_info(GetOnrampContactInfoParameters {
            address: email_only_addr,
            secret: "test_onramp_secret".to_string(),
        })
        .await?;

    assert_eq!(contact_unverified_email.email.as_deref(), Some(email_only));
    assert!(contact_unverified_email.phone.is_none());

    insta::assert_json_snapshot!("contact_info_unverified_email", contact_unverified_email);

    env.relay_handle.storage.verify_email(email_only_addr, email_only, "token456").await?;

    // Test verified state
    let status_email_only = env
        .relay_endpoint
        .onramp_status(OnrampStatusParameters { address: email_only_addr })
        .await?;

    assert!(status_email_only.email.is_some(), "Email timestamp should be present");
    assert!(status_email_only.phone.is_none(), "Phone should be None");

    insta::assert_json_snapshot!("status_email_only", status_email_only, {
        ".email" => "[email_timestamp]",
    });

    let contact_email_only = env
        .relay_endpoint
        .get_onramp_contact_info(GetOnrampContactInfoParameters {
            address: email_only_addr,
            secret: "test_onramp_secret".to_string(),
        })
        .await?;

    assert_eq!(contact_email_only.email.as_deref(), Some(email_only));
    assert!(contact_email_only.phone.is_none());

    insta::assert_json_snapshot!("contact_info_email_only", contact_email_only);

    // Test with unverified account (no email/phone data)
    let unverified_addr = Address::random();
    let status_unverified = env
        .relay_endpoint
        .onramp_status(OnrampStatusParameters { address: unverified_addr })
        .await?;

    assert!(status_unverified.email.is_none(), "Email should be None for unverified account");
    assert!(status_unverified.phone.is_none(), "Phone should be None for unverified account");

    insta::assert_json_snapshot!("status_unverified", status_unverified);

    let contact_unverified = env
        .relay_endpoint
        .get_onramp_contact_info(GetOnrampContactInfoParameters {
            address: unverified_addr,
            secret: "test_onramp_secret".to_string(),
        })
        .await?;

    assert!(contact_unverified.email.is_none());
    assert!(contact_unverified.phone.is_none());

    insta::assert_json_snapshot!("contact_info_unverified", contact_unverified);

    Ok(())
}

/// Creates a reduction that asserts value can be parsed using [`FromStr`], and replaces
/// the value with the provided name.
pub fn reduction_from_str<T: FromStr>(name: &str) -> insta::internals::Redaction {
    let name = name.to_string();
    insta::dynamic_redaction(move |value, _path| {
        assert!(
            T::from_str(value.as_str().unwrap_or_else(|| panic!(
                "cannot parse {:?} as string for field {}",
                std::any::type_name::<T>(),
                name
            )))
            .is_ok()
        );
        format!("[{}]", name)
    })
}
