use crate::e2e::{
    AuthKind, await_calls_status,
    cases::{upgrade::upgrade_account_lazily, upgrade_account_eagerly},
    environment::Environment,
    send_prepared_calls,
};
use alloy::{
    eips::eip7702::constants::EIP7702_DELEGATION_DESIGNATOR,
    primitives::{Address, B256, Bytes, U64, U256},
    providers::{Provider, ext::AnvilApi},
    rpc::types::TransactionRequest,
    sol_types::{SolCall, SolValue},
};
use relay::{
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    types::{
        Account, Call, IERC20,
        IthacaAccount::{self, upgradeProxyAccountCall},
        KeyType, KeyWith712Signer, Signature, SignedCall,
        rpc::{Meta, PrepareCallsCapabilities, PrepareCallsParameters},
    },
};
use std::ops::Div;

/// Ensures unsupported delegation implementations and proxies are caught.
#[tokio::test(flavor = "multi_thread")]
async fn catch_invalid_delegation() -> eyre::Result<()> {
    let env = Environment::setup().await?;
    let caps = env.relay_endpoint.get_capabilities(Some(vec![U64::from(env.chain_id())])).await?;
    let admin_key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();

    // Set up account correctly.
    upgrade_account_eagerly(&env, &[admin_key.to_authorized()], &admin_key, AuthKind::Auth).await?;

    let expected_proxy_code = env
        .provider()
        .get_code_at(caps.chain(env.chain_id()).contracts.delegation_proxy.address)
        .await?;
    let expected_impl_code = env
        .provider()
        .get_code_at(caps.chain(env.chain_id()).contracts.delegation_implementation.address)
        .await?;
    let expected_eoa_code = env.provider().get_code_at(env.eoa.address()).await?;

    let another_impl = Address::random();
    env.provider().anvil_set_code(another_impl, expected_impl_code).await?;

    let params = PrepareCallsParameters {
        from: Some(env.eoa.address()),
        calls: vec![],
        chain_id: env.chain_id(),
        capabilities: PrepareCallsCapabilities {
            authorize_keys: vec![],
            revoke_keys: vec![],
            meta: Meta { fee_payer: None, fee_token: env.fee_token, nonce: None },
            pre_calls: vec![],
            pre_call: false,
            required_funds: vec![],
        },
        state_overrides: Default::default(),
        balance_overrides: Default::default(),
        key: Some(admin_key.to_call_key()),
    };

    let good_quote = env.relay_endpoint.prepare_calls(params.clone()).await?;

    // todo(onbjerg): this assumes a single intent
    assert!(
        good_quote.context.quote().unwrap().ty().quotes[0]
            .intent
            .supported_account_implementation()
            == caps.chain(env.chain_id()).contracts.delegation_implementation.address
    );

    let signed_payload = admin_key.sign_payload_hash(good_quote.digest).await?;

    // Attempt to change delegation implementation to an invalid one and expect it to fail in 3
    // different setups: standalone intent, precall and intent with precall.
    {
        let mut invalid_params = Vec::with_capacity(3);
        let upgrade_call = vec![Call {
            to: env.eoa.address(),
            value: U256::ZERO,
            data: upgradeProxyAccountCall { newImplementation: Address::random() }
                .abi_encode()
                .into(),
        }];

        // As a standalone intent
        let mut standalone = params.clone();
        standalone.calls = upgrade_call.clone();
        invalid_params.push(standalone);

        // As a precall
        let mut precall = params.clone();
        precall.calls = upgrade_call.clone();
        precall.capabilities.pre_call = true;
        invalid_params.push(precall);

        // As a intent with precall
        let mut intent_with_precall = params.clone();
        intent_with_precall.capabilities.pre_calls = vec![SignedCall {
            eoa: env.eoa.address(),
            executionData: upgrade_call.abi_encode().into(),
            nonce: U256::random(),
            signature: Bytes::new(),
        }];
        invalid_params.push(intent_with_precall);

        for p in invalid_params {
            assert!(
                env.relay_endpoint
                    .prepare_calls(p)
                    .await
                    .is_err_and(|err| err.to_string().contains("invalid delegation 0x"))
            )
        }
    }

    // Change the proxy before sending the quote and expect it to fail offchain.
    {
        env.provider()
            .anvil_set_code(
                env.eoa.address(),
                Bytes::from(
                    [&EIP7702_DELEGATION_DESIGNATOR, Address::random().as_slice()].concat(),
                ),
            )
            .await?;

        assert!(
            await_calls_status(
                &env,
                send_prepared_calls(
                    &env,
                    &admin_key,
                    signed_payload.clone(),
                    good_quote.context.clone(),
                )
                .await?
            )
            .await?
            .status
            .is_failed()
        );

        // Reset proxy address on EOA
        env.provider().anvil_set_code(env.eoa.address(), expected_eoa_code.clone()).await?;
    }

    // Change the delegation proxy bytecodecode and prepare_calls & send_prepared_calls should fail.
    {
        let mut code = expected_proxy_code.to_vec();
        code[2] = code[2].wrapping_add(1);
        env.provider()
            .anvil_set_code(
                caps.chain(env.chain_id()).contracts.delegation_proxy.address,
                code.into(),
            )
            .await?;

        assert!(
            env.relay_endpoint
                .prepare_calls(params.clone())
                .await
                .is_err_and(|err| err.to_string().contains("invalid delegation proxy"))
        );

        assert!(
            await_calls_status(
                &env,
                send_prepared_calls(
                    &env,
                    &admin_key,
                    signed_payload.clone(),
                    good_quote.context.clone(),
                )
                .await?
            )
            .await?
            .status
            .is_failed()
        );

        env.provider()
            .anvil_set_code(
                caps.chain(env.chain_id()).contracts.delegation_proxy.address,
                expected_proxy_code,
            )
            .await?;
    }

    // Upgrade implementation to another one and expect it to fail.
    {
        env.provider().anvil_set_code(env.eoa.address(), expected_eoa_code).await?;
        upgrade_delegation(&env, another_impl).await;

        assert!(
            env.relay_endpoint
                .prepare_calls(params.clone())
                .await
                .is_err_and(|err| err.to_string().contains("invalid delegation 0x"))
        );

        assert!(
            await_calls_status(
                &env,
                send_prepared_calls(
                    &env,
                    &admin_key,
                    signed_payload.clone(),
                    good_quote.context.clone(),
                )
                .await?
            )
            .await?
            .status
            .is_failed()
        );
    }

    // Upgrade implementation to original and expect it to succeed sending the intent.
    {
        upgrade_delegation(
            &env,
            caps.chain(env.chain_id()).contracts.delegation_implementation.address,
        )
        .await;

        let fresh_quote = env.relay_endpoint.prepare_calls(params.clone()).await?;
        let fresh_signed_payload = admin_key.sign_payload_hash(fresh_quote.digest).await?;

        assert!(
            await_calls_status(
                &env,
                send_prepared_calls(&env, &admin_key, fresh_signed_payload, fresh_quote.context)
                    .await?
            )
            .await?
            .status
            .is_confirmed()
        );
    }

    Ok(())
}

pub async fn upgrade_delegation(env: &Environment, address: Address) {
    env.provider().anvil_impersonate_account(env.eoa.address()).await.unwrap();
    let tx = TransactionRequest::default()
        .from(env.eoa.address())
        .to(env.eoa.address())
        .input(
            IthacaAccount::upgradeProxyAccountCall { newImplementation: address }
                .abi_encode()
                .into(),
        )
        .gas_limit(100_000);
    let _tx_hash: B256 =
        env.provider().client().request("eth_sendTransaction", (tx,)).await.unwrap();
}

/// Ensures upgradeProxyAccount can be called as a precall.
#[tokio::test(flavor = "multi_thread")]
async fn upgrade_delegation_with_precall() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    let caps = env.relay_endpoint.get_capabilities(Some(vec![U64::from(env.chain_id())])).await?;
    let admin_key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();

    upgrade_account_lazily(&env, &[admin_key.to_authorized()], AuthKind::Auth).await?;

    // Create PreCall with the upgrade call
    let response = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            from: Some(env.eoa.address()),
            calls: vec![Call {
                to: env.eoa.address(),
                value: U256::ZERO,
                data: IthacaAccount::upgradeProxyAccountCall {
                    newImplementation: caps
                        .chain(env.chain_id())
                        .contracts
                        .delegation_implementation
                        .address,
                }
                .abi_encode()
                .into(),
            }],
            chain_id: env.chain_id(),
            capabilities: PrepareCallsCapabilities {
                authorize_keys: vec![],
                revoke_keys: vec![],
                meta: Meta { fee_payer: None, fee_token: env.fee_token, nonce: None },
                pre_calls: vec![],
                pre_call: true,
                required_funds: vec![],
            },
            state_overrides: Default::default(),
            balance_overrides: Default::default(),
            key: Some(admin_key.to_call_key()),
        })
        .await?;

    let mut precall = response.context.take_precall().unwrap();
    precall.signature = Signature {
        innerSignature: admin_key.sign_payload_hash(response.digest).await?,
        keyHash: admin_key.key_hash(),
        prehash: false,
    }
    .abi_encode_packed()
    .into();

    // Create Intent with the upgrade precall call
    let response = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            from: Some(env.eoa.address()),
            calls: vec![],
            chain_id: env.chain_id(),
            capabilities: PrepareCallsCapabilities {
                authorize_keys: vec![],
                revoke_keys: vec![],
                meta: Meta { fee_payer: None, fee_token: env.fee_token, nonce: None },
                pre_calls: vec![precall],
                pre_call: false,
                required_funds: vec![],
            },
            state_overrides: Default::default(),
            balance_overrides: Default::default(),
            key: Some(admin_key.to_call_key()),
        })
        .await?;

    let bundle_id = send_prepared_calls(
        &env,
        &admin_key,
        admin_key.sign_payload_hash(response.digest).await?,
        response.context,
    )
    .await?;

    // Wait for bundle to not be pending.
    let status = await_calls_status(&env, bundle_id).await?;
    assert!(status.status.is_confirmed());

    Ok(())
}

/// Helper function to test delegation upgrade with stored accounts
async fn test_delegation_upgrade_with_stored_account_impl(use_lazy: bool) -> eyre::Result<()> {
    // Start a brand new environment
    let mut env = Environment::setup_multi_chain(2).await?;

    // First restart with legacy (v4) contracts as current
    env.restart_with_v4().await?;

    let admin_key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();

    // Upgrade account either lazily or eagerly based on parameter
    if use_lazy {
        let _auth =
            upgrade_account_lazily(&env, &[admin_key.to_authorized()], AuthKind::Auth).await?;
    } else {
        let _auth =
            upgrade_account_eagerly(&env, &[admin_key.to_authorized()], &admin_key, AuthKind::Auth)
                .await?;
    }

    // Now restart with latest (v5) contracts as current
    env.restart_with_latest().await?;

    let chain_capabilities = &env.relay_endpoint.get_capabilities(None).await?.0[&env.chain_id()];

    // Prepare a call - should auto-add upgrade because account has legacy delegation
    let response = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            from: Some(env.eoa.address()),
            calls: vec![Call::transfer(env.erc20, Address::random(), U256::from(1))],
            chain_id: env.chain_id(),
            capabilities: PrepareCallsCapabilities {
                authorize_keys: vec![],
                revoke_keys: vec![],
                meta: Meta { fee_payer: None, fee_token: env.fee_token, nonce: None },
                pre_calls: vec![],
                pre_call: false,
                required_funds: vec![],
            },
            state_overrides: Default::default(),
            balance_overrides: Default::default(),
            key: Some(admin_key.to_call_key()),
        })
        .await?;

    // Decode the execution data to Vec<Call>
    let quote = response.context.quote().unwrap();

    // Assert that the quote is using v04 Intent (since account was created on v04 orchestrator)
    let intent = &quote.ty().quotes[0].intent;
    assert!(intent.as_v04().is_some());

    let calls = Vec::<Call>::abi_decode(intent.execution_data()).unwrap();

    // Should have user call + upgrade call
    assert_eq!(calls.len(), 2, "Expected exactly two calls (user transfer + upgrade call)");

    // Verify the last call is the upgrade call
    assert_eq!(
        calls[1].data,
        Bytes::from(
            upgradeProxyAccountCall {
                newImplementation: chain_capabilities.contracts.delegation_implementation.address
            }
            .abi_encode()
        ),
        "Last call should be upgradeProxyAccount with current delegation implementation"
    );

    let bundle_id = send_prepared_calls(
        &env,
        &admin_key,
        admin_key.sign_payload_hash(response.digest).await?,
        response.context,
    )
    .await?;

    // Wait for bundle to complete
    let status = await_calls_status(&env, bundle_id).await?;
    assert!(!status.status.is_pending(), "Bundle should not be pending");

    // After upgrade, the account should now be using the latest orchestrator
    assert_eq!(
        Account::new(env.eoa.address(), env.provider()).get_orchestrator().await?,
        env.orchestrator, // Should be using the current (v5) orchestrator
    );

    let response = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            from: Some(env.eoa.address()),
            calls: vec![Call::transfer(env.erc20, Address::random(), U256::from(1))],
            chain_id: env.chain_id(),
            capabilities: PrepareCallsCapabilities {
                authorize_keys: vec![],
                revoke_keys: vec![],
                meta: Meta { fee_payer: None, fee_token: env.fee_token, nonce: None },
                pre_calls: vec![],
                pre_call: false,
                required_funds: vec![],
            },
            state_overrides: Default::default(),
            balance_overrides: Default::default(),
            key: Some(admin_key.to_call_key()),
        })
        .await?;

    // Decode the execution data to Vec<Call>
    let quote = response.context.quote().unwrap();

    // Assert that the quote is using v05 Intent (since we have upgraded it)
    let intent = &quote.ty().quotes[0].intent;
    assert!(intent.as_v05().is_some());

    let calls = Vec::<Call>::abi_decode(intent.execution_data()).unwrap();

    // Should have user call
    assert_eq!(calls.len(), 1, "Expected exactly 1 call (user transfer)");

    let bundle_id = send_prepared_calls(
        &env,
        &admin_key,
        admin_key.sign_payload_hash(response.digest).await?,
        response.context,
    )
    .await?;

    // Wait for bundle to complete
    let status = await_calls_status(&env, bundle_id).await?;
    assert!(!status.status.is_pending(), "Bundle should not be pending");

    // Now test a multichain transfer where the chain0 account is on v5, but the chain1 account is
    // not yet deployed but stored in db as v4

    // Check balances on both chains
    let chain0_balance =
        IERC20::new(env.erc20, env.provider_for(0)).balanceOf(env.eoa.address()).call().await?;
    let chain1_balance =
        IERC20::new(env.erc20, env.provider_for(1)).balanceOf(env.eoa.address()).call().await?;

    // Create a transfer on chain 0 that requires MORE funds than available on chain 0
    // This will force pulling funds from chain 1
    let required_amount = chain0_balance + chain1_balance.div(U256::from(2)); // More than what's on chain 0

    let multichain_response = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            from: Some(env.eoa.address()),
            calls: vec![Call::transfer(env.erc20, Address::random(), U256::from(100))],
            chain_id: env.chain_id_for(0),
            capabilities: PrepareCallsCapabilities {
                authorize_keys: vec![],
                revoke_keys: vec![],
                meta: Meta { fee_payer: None, fee_token: env.erc20, nonce: None },
                pre_calls: vec![],
                pre_call: false,
                // Request more funds than available on chain 0 to trigger multichain
                required_funds: vec![relay::types::rpc::RequiredAsset::new(
                    env.erc20,
                    required_amount,
                )],
            },
            state_overrides: Default::default(),
            balance_overrides: Default::default(),
            key: Some(admin_key.to_call_key()),
        })
        .await?;

    let mc_quote = multichain_response.context.quote().unwrap();
    assert_eq!(mc_quote.ty().quotes.len(), 2, "Should have exactly 2 quotes for 2-chain transfer");

    // Chain0 (Destination intent) has been upgraded to v05
    let has_v05 = mc_quote.ty().quotes[1].intent.as_v05().is_some();

    // Chain1 (Escrow intent) is using the stored account, so it needs an upgrade at the end
    let has_v04 = mc_quote.ty().quotes[0].intent.as_v04().is_some();
    assert!(has_v04 && has_v05, "Multichain transfer should have one V04 and one V05 Intent");

    let v04_calls =
        Vec::<Call>::abi_decode(mc_quote.ty().quotes[0].intent.execution_data()).unwrap();
    // Other two calls are approve and escrow
    assert!(v04_calls[2].data[..4] == upgradeProxyAccountCall::SELECTOR);

    // Execute the multichain transfer
    let mc_bundle_id = send_prepared_calls(
        &env,
        &admin_key,
        admin_key.sign_payload_hash(multichain_response.digest).await?,
        multichain_response.context,
    )
    .await?;

    // Wait for multichain bundle to complete
    let mc_status = await_calls_status(&env, mc_bundle_id).await?;
    assert!(mc_status.status.is_confirmed(), "Multichain transfer should be confirmed");

    Ok(())
}

/// Test that delegation upgrade happens even with accounts only stored and not onchain.
#[tokio::test]
async fn test_delegation_auto_upgrade_with_stored_account() -> eyre::Result<()> {
    // Skip this test if DATABASE_URL is not set
    if std::env::var("DATABASE_URL").is_err() {
        // We restart the relay, and so we need a persistent storage
        return Ok(());
    }

    // Test upgrade from a stored/offchain account
    test_delegation_upgrade_with_stored_account_impl(true).await?;

    // Test upgrade from a onchain account
    test_delegation_upgrade_with_stored_account_impl(false).await?;

    Ok(())
}

/// Test that delegation upgrade is automatically added when EOA has legacy delegation
#[tokio::test]
async fn test_delegation_auto_upgrade() -> eyre::Result<()> {
    let env = Environment::setup().await.unwrap();

    let admin_key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();
    upgrade_account_eagerly(&env, &[admin_key.to_authorized()], &admin_key, AuthKind::Auth).await?;
    let chain_capabilities = &env.relay_endpoint.get_capabilities(None).await?.0[&env.chain_id()];

    // Force EOA to delegation proxy and delegation impl
    upgrade_delegation(&env, chain_capabilities.contracts.legacy_delegations[0].address).await;
    env.provider()
        .anvil_set_code(
            env.eoa.address(),
            Bytes::from(
                [&EIP7702_DELEGATION_DESIGNATOR, env.get_legacy_delegation_proxy().as_slice()]
                    .concat(),
            ),
        )
        .await?;

    assert_eq!(
        Account::new(env.eoa.address(), env.provider()).delegation_implementation().await?,
        Some(chain_capabilities.contracts.legacy_delegations[0].address),
        "Account delegation should be set to legacy"
    );

    let response = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            from: Some(env.eoa.address()),
            calls: vec![Call::transfer(env.erc20, Address::random(), U256::from(1))],
            chain_id: env.chain_id(),
            capabilities: PrepareCallsCapabilities {
                authorize_keys: vec![],
                revoke_keys: vec![],
                meta: Meta { fee_payer: None, fee_token: env.fee_token, nonce: None },
                pre_calls: vec![],
                pre_call: false,
                required_funds: vec![],
            },
            state_overrides: Default::default(),
            balance_overrides: Default::default(),
            key: Some(admin_key.to_call_key()),
        })
        .await?;

    // Decode the execution data to Vec<Call>
    let calls = Vec::<Call>::abi_decode(
        response.context.quote().unwrap().ty().quotes[0].intent.execution_data(),
    )
    .unwrap();
    assert_eq!(calls.len(), 2, "Expected exactly two calls (user transfer + upgrade call)");

    // Verify the last call is the upgrade call
    assert_eq!(
        calls[1].data,
        Bytes::from(
            upgradeProxyAccountCall {
                newImplementation: chain_capabilities.contracts.delegation_implementation.address
            }
            .abi_encode()
        ),
        "Last call should be upgradeProxyAccount with current delegation implementation"
    );
    let bundle_id = send_prepared_calls(
        &env,
        &admin_key,
        admin_key.sign_payload_hash(response.digest).await?,
        response.context,
    )
    .await?;

    // Wait for bundle to not be pending.
    let status = await_calls_status(&env, bundle_id).await?;
    assert!(status.status.is_confirmed(), "{status:?}");

    // Verify the delegation was upgraded to the new one
    assert_eq!(
        Account::new(env.eoa.address(), env.provider()).delegation_implementation().await?,
        Some(chain_capabilities.contracts.delegation_implementation.address),
        "Account delegation should be upgraded to the current delegation"
    );

    Ok(())
}
