//! Paymaster related end-to-end test cases

use crate::e2e::{
    AuthKind, await_calls_status,
    environment::{Environment, mint_erc20s},
    eoa::{MockAccount, MockAccountBuilder},
};
use alloy::{
    primitives::{Address, B256, U256},
    providers::{Provider, ext::AnvilApi},
    sol_types::SolValue,
};
use relay::{
    rpc::RelayApiClient,
    signers::{DynSigner, Eip712PayLoadSigner},
    types::{
        IERC20, KeyType, KeyWith712Signer, Signature,
        rpc::{
            Meta, PrepareCallsCapabilities, PrepareCallsParameters, PrepareCallsResponse,
            PrepareUpgradeAccountParameters, SendPreparedCallsCapabilities,
            SendPreparedCallsParameters, UpgradeAccountCapabilities, UpgradeAccountParameters,
            UpgradeAccountSignatures,
        },
    },
};

#[tokio::test(flavor = "multi_thread")]
async fn use_external_fee_payer() -> eyre::Result<()> {
    let env: Environment = Environment::setup().await?;

    // Create eoa and paymaster accounts
    let eoa = MockAccount::new(&env).await?;
    let paymaster = MockAccount::new(&env).await?;

    // Mint ERC20 fee token
    mint_erc20s(&[env.erc20], &[eoa.address, paymaster.address], env.provider()).await?;

    let balance = async |acc: Address, fee_token: Address| {
        if fee_token.is_zero() {
            return env.provider().get_balance(acc).await.unwrap();
        }
        IERC20::IERC20Instance::new(fee_token, env.provider()).balanceOf(acc).call().await.unwrap()
    };

    for fee_token in [Address::ZERO, env.erc20] {
        let pre_paymaster_balance = balance(paymaster.address, fee_token).await;
        let pre_eoa_balance = balance(eoa.address, fee_token).await;

        let PrepareCallsResponse { mut context, digest, .. } = env
            .relay_endpoint
            .prepare_calls(PrepareCallsParameters {
                calls: vec![],
                chain_id: env.chain_id(),
                from: Some(eoa.address),
                capabilities: PrepareCallsCapabilities {
                    authorize_keys: vec![],
                    meta: Meta {
                        fee_payer: Some(paymaster.address),
                        fee_token: Some(fee_token),
                        nonce: None,
                    },
                    pre_calls: vec![],
                    pre_call: false,
                    revoke_keys: vec![],
                    required_funds: vec![],
                },
                state_overrides: Default::default(),
                balance_overrides: Default::default(),
                key: Some(eoa.key.to_call_key()),
            })
            .await
            .unwrap();

        // Ensure the payer on Intent is as expected
        // todo(onbjerg): this assumes a single intent
        assert_eq!(context.quote_mut().unwrap().ty().quotes[0].intent.payer(), paymaster.address);

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
                key: Some(eoa.key.to_call_key()),
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

/// Test that delegation upgrade is automatically added when EOA has legacy delegation
#[tokio::test]
async fn test_paymaster_auto_upgrade() -> eyre::Result<()> {
    let env: Environment = Environment::setup().await?;

    // Create eoa and paymaster account
    let eoa = MockAccountBuilder::new().build(&env).await?;
    let fee_token = env.erc20;

    let paymaster_eoa = DynSigner::from_signing_key(&B256::random().to_string()).await?;
    let paymaster_key =
        KeyWith712Signer::mock_admin_with_key(KeyType::Secp256k1, B256::random())?.unwrap();

    // Call prepare_upgrade_account for paymaster
    let response = env
        .relay_endpoint
        .prepare_upgrade_account(PrepareUpgradeAccountParameters {
            address: paymaster_eoa.address(),
            delegation: env.delegation,
            chain_id: None,
            capabilities: UpgradeAccountCapabilities {
                authorize_keys: vec![paymaster_key.to_authorized()],
            },
        })
        .await?;

    let exec_sig = paymaster_eoa.sign_hash(&response.digests.exec).await?;
    let nonce = env.provider().get_transaction_count(paymaster_eoa.address()).await?;
    let auth = AuthKind::modified_signer(paymaster_eoa.clone()).sign(&env, nonce).await?;

    // Upgrade the account, should cause it to be stored in the relay
    env.relay_endpoint
        .upgrade_account(UpgradeAccountParameters {
            context: response.context,
            signatures: UpgradeAccountSignatures { auth: auth.signature()?, exec: exec_sig },
        })
        .await?;

    // Give paymaster ETH for gas
    env.provider().anvil_set_balance(paymaster_eoa.address(), U256::from(100e18)).await?;

    let paymaster_addr = paymaster_eoa.address();

    // Mint ERC20 fee token
    mint_erc20s(&[fee_token], &[eoa.address, paymaster_addr], env.provider()).await?;

    let balance = async |acc: Address, fee_token: Address| {
        if fee_token.is_zero() {
            return env.provider().get_balance(acc).await.unwrap();
        }
        IERC20::IERC20Instance::new(fee_token, env.provider()).balanceOf(acc).call().await.unwrap()
    };

    let pre_paymaster_balance = balance(paymaster_addr, fee_token).await;
    let pre_eoa_balance = balance(eoa.address, fee_token).await;

    let PrepareCallsResponse { mut context, digest, .. } = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            chain_id: env.chain_id(),
            from: Some(eoa.address),
            capabilities: PrepareCallsCapabilities {
                meta: Meta {
                    fee_payer: Some(paymaster_addr),
                    fee_token: Some(fee_token),
                    nonce: None,
                },
                ..Default::default()
            },
            key: Some(eoa.key.to_call_key()),
            ..Default::default()
        })
        .await
        .unwrap();

    // Ensure the payer on Intent is as expected
    // todo(onbjerg): this assumes a single intent
    assert_eq!(context.quote_mut().unwrap().ty().quotes[0].intent.payer(), paymaster_addr);

    let bundle_id = env
        .relay_endpoint
        .send_prepared_calls(SendPreparedCallsParameters {
            capabilities: SendPreparedCallsCapabilities {
                fee_signature: Signature {
                    innerSignature: paymaster_key.sign_payload_hash(digest).await.unwrap(),
                    keyHash: paymaster_key.key_hash(),
                    prehash: false,
                }
                .abi_encode_packed()
                .into(),
            },
            context,
            key: Some(eoa.key.to_call_key()),
            signature: eoa.key.sign_payload_hash(digest).await.unwrap(),
        })
        .await?
        .id;

    // Wait for bundle to not be pending.
    let status = await_calls_status(&env, bundle_id).await?;
    assert!(status.status.is_final());

    let post_paymaster_balance = balance(paymaster_addr, fee_token).await;
    let post_eoa_balance = balance(eoa.address, fee_token).await;

    assert_eq!(pre_eoa_balance, post_eoa_balance);
    assert!(pre_paymaster_balance > post_paymaster_balance);

    Ok(())
}
