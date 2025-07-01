use crate::e2e::{
    AuthKind, await_calls_status,
    cases::{upgrade::upgrade_account_lazily, upgrade_account_eagerly},
    environment::Environment,
    send_prepared_calls,
};
use alloy::{
    eips::eip7702::constants::EIP7702_DELEGATION_DESIGNATOR,
    primitives::{B256, Bytes},
    providers::{Provider, ext::AnvilApi},
    rpc::types::TransactionRequest,
    sol_types::{SolCall, SolValue},
};
use alloy_primitives::{Address, U256};
use relay::{
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    types::{
        Call,
        IthacaAccount::{self, upgradeProxyAccountCall},
        KeyType, KeyWith712Signer, Signature, SignedCall,
        rpc::{Meta, PrepareCallsCapabilities, PrepareCallsParameters},
    },
};

/// Ensures unsupported delegation implementations and proxies are caught.
#[tokio::test(flavor = "multi_thread")]
async fn catch_invalid_delegation() -> eyre::Result<()> {
    let env = Environment::setup().await?;
    let caps = env.relay_endpoint.get_capabilities(vec![env.chain_id()]).await?;
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
        required_funds: vec![],
        from: Some(env.eoa.address()),
        calls: vec![],
        chain_id: env.chain_id(),
        capabilities: PrepareCallsCapabilities {
            authorize_keys: vec![],
            revoke_keys: vec![],
            meta: Meta { fee_payer: None, fee_token: env.fee_token, nonce: None },
            pre_calls: vec![],
            pre_call: false,
        },
        state_overrides: Default::default(),
        key: Some(admin_key.to_call_key()),
    };

    let good_quote = env.relay_endpoint.prepare_calls(params.clone()).await?;

    // todo(onbjerg): this assumes a single intent
    assert!(
        good_quote.context.quote().unwrap().ty().quotes[0].intent.supportedAccountImplementation
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

async fn upgrade_delegation(env: &Environment, address: Address) {
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

    let caps = env.relay_endpoint.get_capabilities(vec![env.chain_id()]).await?;
    let admin_key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();

    upgrade_account_lazily(&env, &[admin_key.to_authorized()], AuthKind::Auth).await?;

    // Create PreCall with the upgrade call
    let response = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            required_funds: vec![],
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
            },
            state_overrides: Default::default(),
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
            required_funds: vec![],
            from: Some(env.eoa.address()),
            calls: vec![],
            chain_id: env.chain_id(),
            capabilities: PrepareCallsCapabilities {
                authorize_keys: vec![],
                revoke_keys: vec![],
                meta: Meta { fee_payer: None, fee_token: env.fee_token, nonce: None },
                pre_calls: vec![precall],
                pre_call: false,
            },
            state_overrides: Default::default(),
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
