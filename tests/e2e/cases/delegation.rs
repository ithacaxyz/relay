use crate::e2e::{
    ExpectedOutcome, TxContext, await_calls_status, cases::prep_account, environment::Environment,
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
        Delegation::{self},
        KeyType, KeyWith712Signer, Signature,
        rpc::{Meta, PrepareCallsCapabilities, PrepareCallsParameters},
    },
};

/// Ensures unsupported delegation implementations and proxies are caught.
#[tokio::test(flavor = "multi_thread")]
async fn catch_invalid_delegation() -> eyre::Result<()> {
    let mut env = Environment::setup_with_prep().await?;
    let caps = env.relay_endpoint.get_capabilities().await?;
    let admin_key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();

    // Set up PREP account correctly.
    {
        prep_account(&mut env, &[&admin_key]).await?;
        TxContext { expected: ExpectedOutcome::Pass, key: Some(&admin_key), ..Default::default() }
            .process(0, &env)
            .await?;
    }

    let expected_proxy_code = env.provider.get_code_at(caps.contracts.delegation_proxy).await?;
    let expected_impl_code =
        env.provider.get_code_at(caps.contracts.delegation_implementation).await?;
    let expected_eoa_code = env.provider.get_code_at(env.eoa.address()).await?;

    let another_impl = Address::random();
    env.provider.anvil_set_code(another_impl, expected_impl_code).await?;

    let params = PrepareCallsParameters {
        from: Some(env.eoa.address()),
        calls: vec![],
        chain_id: env.chain_id,
        capabilities: PrepareCallsCapabilities {
            authorize_keys: vec![],
            revoke_keys: vec![],
            meta: Meta { fee_payer: None, fee_token: env.fee_token, nonce: None },
            pre_ops: vec![],
            pre_op: false,
        },
        key: Some(admin_key.to_call_key()),
    };

    let good_quote = env.relay_endpoint.prepare_calls(params.clone()).await?;

    assert!(
        good_quote.context.quote().unwrap().ty().op.supportedDelegationImplementation
            == caps.contracts.delegation_implementation
    );

    let signed_payload = admin_key.sign_payload_hash(good_quote.digest).await?;

    // Change the proxy before sending the quote and expect it to fail offchain.
    {
        env.provider
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
        env.provider.anvil_set_code(env.eoa.address(), expected_eoa_code.clone()).await?;
    }

    // Change the delegation proxy bytecodecode and prepare_calls & send_prepared_calls should fail.
    {
        let mut code = expected_proxy_code.to_vec();
        code[2] = code[2].wrapping_add(1);
        env.provider.anvil_set_code(caps.contracts.delegation_proxy, code.into()).await?;

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

        env.provider.anvil_set_code(caps.contracts.delegation_proxy, expected_proxy_code).await?;
    }

    // Upgrade implementation to another one and expect it to fail.
    {
        env.provider.anvil_set_code(env.eoa.address(), expected_eoa_code).await?;
        upgrade_delegation(&env, another_impl).await;

        assert!(
            env.relay_endpoint
                .prepare_calls(params)
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

    // Upgrade implementation to original and expect it to succeed sending the userop.
    {
        upgrade_delegation(&env, caps.contracts.delegation_implementation).await;

        assert!(
            await_calls_status(
                &env,
                send_prepared_calls(&env, &admin_key, signed_payload, good_quote.context).await?
            )
            .await?
            .status
            .is_confirmed()
        );
    }

    Ok(())
}

async fn upgrade_delegation(env: &Environment, address: Address) {
    env.provider.anvil_impersonate_account(env.eoa.address()).await.unwrap();
    let tx = TransactionRequest::default()
        .from(env.eoa.address())
        .to(env.eoa.address())
        .input(
            Delegation::upgradeProxyDelegationCall { newImplementation: address }
                .abi_encode()
                .into(),
        )
        .gas_limit(100_000);
    let _tx_hash: B256 = env.provider.client().request("eth_sendTransaction", (tx,)).await.unwrap();
}

/// Ensures upgradeProxyDelegation can be called as a preop.
#[tokio::test(flavor = "multi_thread")]
async fn upgrade_delegation_with_preop() -> eyre::Result<()> {
    let mut env = Environment::setup_with_prep().await?;

    let caps = env.relay_endpoint.get_capabilities().await?;
    let admin_key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();

    prep_account(&mut env, &[&admin_key]).await?;

    // Create PreOp with the upgrade call
    let response = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            from: Some(env.eoa.address()),
            calls: vec![Call {
                to: env.eoa.address(),
                value: U256::ZERO,
                data: Delegation::upgradeProxyDelegationCall {
                    newImplementation: caps.contracts.delegation_implementation,
                }
                .abi_encode()
                .into(),
            }],
            chain_id: env.chain_id,
            capabilities: PrepareCallsCapabilities {
                authorize_keys: vec![],
                revoke_keys: vec![],
                meta: Meta { fee_payer: None, fee_token: env.fee_token, nonce: None },
                pre_ops: vec![],
                pre_op: true,
            },
            key: Some(admin_key.to_call_key()),
        })
        .await?;

    let mut preop = response.context.take_preop().unwrap();
    preop.signature = Signature {
        innerSignature: admin_key.sign_payload_hash(response.digest).await?,
        keyHash: admin_key.key_hash(),
        prehash: false,
    }
    .abi_encode_packed()
    .into();

    // Create UserOp with the upgrade preop call
    let response = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            from: Some(env.eoa.address()),
            calls: vec![],
            chain_id: env.chain_id,
            capabilities: PrepareCallsCapabilities {
                authorize_keys: vec![],
                revoke_keys: vec![],
                meta: Meta { fee_payer: None, fee_token: env.fee_token, nonce: None },
                pre_ops: vec![preop],
                pre_op: false,
            },
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
