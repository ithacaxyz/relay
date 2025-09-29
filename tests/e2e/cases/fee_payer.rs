//! Tests for fee_payer functionality

use crate::e2e::{
    AuthKind, await_calls_status,
    cases::upgrade_account_eagerly,
    environment::{Environment, mint_erc20s},
    eoa::MockAccount,
};
use alloy::{
    primitives::{Address, U256},
    providers::ext::AnvilApi,
    sol_types::SolValue,
};
use eyre::Result;
use relay::{
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    types::{
        Call, IERC20, KeyType, KeyWith712Signer, Signature,
        rpc::{
            Meta, PrepareCallsCapabilities, PrepareCallsParameters, SendPreparedCallsCapabilities,
            SendPreparedCallsParameters,
        },
    },
};

#[tokio::test(flavor = "multi_thread")]
async fn test_fee_payer_delegation() -> Result<()> {
    let env = Environment::setup().await?;
    let main_key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();
    let fee_payer = MockAccount::new(&env).await?;

    // Fund accounts
    env.provider().anvil_set_balance(fee_payer.address, U256::from(10e18)).await?;
    mint_erc20s(&[env.erc20], &[fee_payer.address, env.eoa.address()], env.provider()).await?;

    // Upgrade main EOA
    upgrade_account_eagerly(&env, &[main_key.to_authorized()], &main_key, AuthKind::Auth).await?;

    // Track balances
    let erc20 = IERC20::IERC20Instance::new(env.erc20, env.provider());
    let initial_main_balance = erc20.balanceOf(env.eoa.address()).call().await?;
    let initial_fee_payer_balance = erc20.balanceOf(fee_payer.address).call().await?;

    // Prepare transfer with fee payer
    let recipient = Address::random();
    let transfer_amount = U256::from(100);

    let response = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            from: Some(env.eoa.address()),
            calls: vec![Call::transfer(env.erc20, recipient, transfer_amount)],
            chain_id: env.chain_id(),
            capabilities: PrepareCallsCapabilities {
                meta: Meta {
                    fee_payer: Some(fee_payer.address),
                    fee_token: Some(env.erc20), // Use same ERC20 for fees
                    nonce: None,
                },
                authorize_keys: vec![],
                revoke_keys: vec![],
                pre_calls: vec![],
                pre_call: false,
                required_funds: vec![],
            },
            state_overrides: Default::default(),
            balance_overrides: Default::default(),
            key: Some(main_key.to_call_key()),
        })
        .await?;

    // Verify fee payer is set in quote
    let quote = response.context.quote().expect("Should have quote context");
    assert_eq!(quote.ty().quotes[0].intent.payer(), fee_payer.address);

    // Sign and send with fee payer signature
    let signature = main_key.sign_payload_hash(response.digest).await?;
    let fee_signature = Signature {
        innerSignature: fee_payer.key.sign_payload_hash(response.digest).await?,
        keyHash: fee_payer.key.key_hash(),
        prehash: false,
    }
    .abi_encode_packed()
    .into();

    let send_response = env
        .relay_endpoint
        .send_prepared_calls(SendPreparedCallsParameters {
            context: response.context,
            signature,
            capabilities: SendPreparedCallsCapabilities { fee_signature },
            key: Some(main_key.to_call_key()),
        })
        .await?;

    // Verify transaction succeeded
    let status = await_calls_status(&env, send_response.id).await?;
    assert!(status.status.is_confirmed());

    // Verify balances: main account only transferred tokens (no fees), fee payer paid fees
    assert_eq!(
        erc20.balanceOf(env.eoa.address()).call().await?,
        initial_main_balance - transfer_amount
    );
    assert_eq!(erc20.balanceOf(recipient).call().await?, transfer_amount);
    assert!(erc20.balanceOf(fee_payer.address).call().await? < initial_fee_payer_balance);

    Ok(())
}
