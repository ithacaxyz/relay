use crate::e2e::{
    await_calls_status, environment::Environment, eoa::MockAccount, send_prepared_calls,
};
use alloy::{
    primitives::B256,
    providers::{Provider, ext::AnvilApi},
    rpc::types::TransactionRequest,
    sol_types::SolCall,
};
use alloy_primitives::{Address, U256};
use relay::{
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    types::{
        OrchestratorContract::{self, OrchestratorContractInstance},
        rpc::{Meta, PrepareCallsCapabilities, PrepareCallsParameters},
    },
};

#[tokio::test(flavor = "multi_thread")]
async fn pause() -> eyre::Result<()> {
    let env: Environment = Environment::setup_with_prep().await?;
    let eoa = MockAccount::new(&env).await?;
    let orchestrator = OrchestratorContractInstance::new(env.orchestrator, &env.provider);

    let prepare_params = PrepareCallsParameters {
        from: Some(eoa.address),
        calls: vec![],
        chain_id: env.chain_id,
        capabilities: PrepareCallsCapabilities {
            authorize_keys: vec![],
            revoke_keys: vec![],
            meta: Meta { fee_payer: None, fee_token: Address::ZERO, nonce: None },
            pre_calls: vec![],
            pre_call: false,
        },
        key: Some(eoa.key.to_call_key()),
    };

    // Can call prepareCalls
    let response = env.relay_endpoint.prepare_calls(prepare_params.clone()).await?;

    // Pause all
    let pauser = orchestrator.getPauseConfig().call().await?._0;
    env.provider.anvil_set_balance(pauser, U256::MAX).await.unwrap();
    env.provider.anvil_impersonate_account(pauser).await.unwrap();
    let _tx_hash: B256 = env
        .provider
        .client()
        .request(
            "eth_sendTransaction",
            (TransactionRequest::default()
                .from(pauser)
                .to(env.orchestrator)
                .input(OrchestratorContract::pauseCall { isPause: true }.abi_encode().into())
                .gas_limit(100_000),),
        )
        .await
        .unwrap();

    // should be paused
    assert!(orchestrator.pauseFlag().call().await? == U256::from(1));

    // prepare calls should fail
    assert!(
        env.relay_endpoint
            .prepare_calls(prepare_params.clone())
            .await
            .is_err_and(|err| err.to_string().contains("paused"))
    );

    // sending prepared calls should fail
    let bundle_id = send_prepared_calls(
        &env,
        &eoa.key,
        eoa.key.sign_payload_hash(response.digest).await?,
        response.context,
    )
    .await?;

    // wait for bundle to not be pending.
    let status = await_calls_status(&env, bundle_id).await?;
    assert!(status.status.is_failed());

    // unpause
    let _tx_hash: B256 = env
        .provider
        .client()
        .request(
            "eth_sendTransaction",
            (TransactionRequest::default()
                .from(pauser)
                .to(env.orchestrator)
                .input(OrchestratorContract::pauseCall { isPause: false }.abi_encode().into())
                .gas_limit(100_000),),
        )
        .await
        .unwrap();

    // prepare calls should pass
    let response = env.relay_endpoint.prepare_calls(prepare_params.clone()).await?;

    // sending prepared calls should pass
    let bundle_id = send_prepared_calls(
        &env,
        &eoa.key,
        eoa.key.sign_payload_hash(response.digest).await?,
        response.context,
    )
    .await?;

    // wait for bundle to not be pending.
    let status = await_calls_status(&env, bundle_id).await?;
    assert!(status.status.is_confirmed());

    Ok(())
}
