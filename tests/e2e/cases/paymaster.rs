//! Paymaster related end-to-end test cases

use crate::e2e::{
    await_calls_status,
    environment::{Environment, mint_erc20s},
    eoa::MockAccount,
};
use alloy::{primitives::Address, providers::Provider, sol_types::SolValue};
use relay::{
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    types::{
        IERC20, Signature,
        rpc::{
            Meta, PrepareCallsCapabilities, PrepareCallsParameters, PrepareCallsResponse,
            SendPreparedCallsCapabilities, SendPreparedCallsParameters,
        },
    },
};

#[tokio::test(flavor = "multi_thread")]
async fn use_external_fee_payer() -> eyre::Result<()> {
    let env: Environment = Environment::setup_with_prep().await?;

    // Create eoa and paymaster prep accounts
    let eoa = MockAccount::new(&env).await?;
    let paymaster = MockAccount::new(&env).await?;

    // Mint ERC20 fee token
    mint_erc20s(&[env.fee_token], &[eoa.address, paymaster.address], &env.provider).await?;

    let balance = async |acc: Address, fee_token: Address| {
        if fee_token.is_zero() {
            return env.provider.get_balance(acc).await.unwrap();
        }
        IERC20::IERC20Instance::new(fee_token, &env.provider).balanceOf(acc).call().await.unwrap()
    };

    for fee_token in [Address::ZERO, env.fee_token] {
        let pre_paymaster_balance = balance(paymaster.address, fee_token).await;
        let pre_eoa_balance = balance(eoa.address, fee_token).await;

        let PrepareCallsResponse { mut context, digest, .. } = env
            .relay_endpoint
            .prepare_calls(PrepareCallsParameters {
                calls: vec![],
                chain_id: env.chain_id,
                from: Some(eoa.address),
                capabilities: PrepareCallsCapabilities {
                    authorize_keys: vec![],
                    meta: Meta { fee_payer: Some(paymaster.address), fee_token, nonce: None },
                    pre_ops: vec![],
                    pre_op: false,
                    revoke_keys: vec![],
                },
                key: Some(eoa.key.to_call_key()),
            })
            .await
            .unwrap();

        // Ensure the payer on UserOp is as expected
        assert_eq!(context.quote_mut().unwrap().ty().op.payer, paymaster.address);

        let bundle_id = env
            .relay_endpoint
            .send_prepared_calls(SendPreparedCallsParameters {
                capabilities: SendPreparedCallsCapabilities {
                    fee_signature: Signature {
                        innerSignature: paymaster.key.sign_payload_hash(digest).await.unwrap(),
                        keyHash: paymaster.key.key_hash(),
                        prehash: false,
                    }
                    .abi_encode_packed()
                    .into(),
                },
                context,
                key: eoa.key.to_call_key(),
                signature: eoa.key.sign_payload_hash(digest).await.unwrap(),
            })
            .await?
            .id;

        // Wait for bundle to not be pending.
        let status = await_calls_status(&env, bundle_id).await?;
        assert!(status.status.is_final());

        let post_paymaster_balance = balance(paymaster.address, fee_token).await;
        let post_eoa_balance = balance(eoa.address, fee_token).await;

        assert_eq!(pre_eoa_balance, post_eoa_balance);
        assert!(pre_paymaster_balance > post_paymaster_balance);
    }

    Ok(())
}
