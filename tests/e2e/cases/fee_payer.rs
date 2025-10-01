//! Tests for fee_payer functionality

use crate::e2e::{
    AuthKind, await_calls_status,
    cases::upgrade_account_eagerly,
    environment::{Environment, mint_erc20s},
    eoa::{MockAccount, MockAccountBuilder},
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
    assert!(response.digest == response.capabilities.fee_payer_digest.unwrap());
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

#[tokio::test(flavor = "multi_thread")]
async fn test_cross_chain_fee_payer() -> Result<()> {
    // Setup environment with 2 chains for cross-chain fee payer
    let env = Environment::setup_multi_chain(2).await?;
    let main_key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();

    // Upgrade main EOA on both chains
    upgrade_account_eagerly(&env, &[main_key.to_authorized()], &main_key, AuthKind::Auth).await?;

    // Create fee_payer account using MockAccountBuilder with no ERC20 mint
    let fee_payer = MockAccountBuilder::new().no_erc20_mint().build(&env).await?;

    // Fund user on chain 0, fee_payer on chain 1 only
    let chain_0_provider = env.provider_for(0);
    let chain_1_provider = env.provider_for(1);

    // Give user ERC20 tokens on chain 0 for the transfer
    mint_erc20s(&[env.erc20], &[env.eoa.address()], chain_0_provider).await?;

    // Give fee_payer ERC20 tokens ONLY on chain 1 (for cross-chain fee payment)
    // Mint multiple times to ensure fee_payer has enough for user fees + their own gas
    mint_erc20s(&[env.erc20], &[fee_payer.address], chain_1_provider).await?;

    // Track balances
    let erc20_chain0 = IERC20::IERC20Instance::new(env.erc20, chain_0_provider);
    let erc20_chain1 = IERC20::IERC20Instance::new(env.erc20, chain_1_provider);

    let initial_user_balance_chain0 = erc20_chain0.balanceOf(env.eoa.address()).call().await?;
    let initial_fee_payer_balance_chain1 = erc20_chain1.balanceOf(fee_payer.address).call().await?;

    // Prepare transfer on chain 0 with fee_payer that only has funds on chain 1
    let recipient = Address::random();
    let transfer_amount = U256::from(100);

    let response = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            from: Some(env.eoa.address()),
            calls: vec![Call::transfer(env.erc20, recipient, transfer_amount)],
            chain_id: env.chain_id_for(0),
            key: Some(main_key.to_call_key()),
            capabilities: PrepareCallsCapabilities {
                meta: Meta {
                    fee_payer: Some(fee_payer.address),
                    fee_token: Some(env.erc20),
                    nonce: None,
                },
                ..Default::default()
            },
            ..Default::default()
        })
        .await?;

    // Verify this is a cross-chain fee payer case
    let quote = response.context.quote().expect("Should have quote context");
    assert_eq!(quote.ty().quotes.len(), 1, "Should have 1 user quote");
    assert!(quote.ty().fee_payer.is_some(), "Should have cross-chain fee_payer quote");

    let fee_payer_quote = quote.ty().fee_payer.as_ref().unwrap();
    assert_eq!(
        fee_payer_quote.chain_id,
        env.chain_id_for(1),
        "Fee payer should execute on chain 1"
    );

    // Verify fee_payer_digest is present in capabilities
    assert!(
        response.capabilities.fee_payer_digest.is_some(),
        "Should have fee_payer_digest for signing"
    );

    // Intent on destination is free with no payer.
    assert!(quote.ty().quotes[0].intent.payer() == Address::ZERO);
    assert!(quote.ty().quotes[0].intent.total_payment_max_amount() == U256::ZERO);

    // Sign user intent
    let user_signature = main_key.sign_payload_hash(response.digest).await?;

    // Payer digest is different than user digest
    let fee_payer_digest = response.capabilities.fee_payer_digest.unwrap();
    assert!(response.digest != fee_payer_digest);
    let fee_signature = Signature {
        innerSignature: fee_payer.key.sign_payload_hash(fee_payer_digest).await?,
        keyHash: fee_payer.key.key_hash(),
        prehash: false,
    }
    .abi_encode_packed()
    .into();

    // Send prepared calls
    let send_response = env
        .relay_endpoint
        .send_prepared_calls(SendPreparedCallsParameters {
            context: response.context,
            signature: user_signature,
            capabilities: SendPreparedCallsCapabilities { fee_signature },
            key: Some(main_key.to_call_key()),
        })
        .await?;

    // Verify transaction succeeded
    let status = await_calls_status(&env, send_response.id).await?;
    assert!(status.status.is_confirmed(), "Transaction should succeed: {:?}", status.status);
    assert!(status.capabilities.unwrap().interop_status.unwrap().is_done());

    // Verify balances:
    // - User on chain 0: transferred tokens (no fees paid)
    // - Fee payer on chain 1: paid fees
    // - Recipient on chain 0: received tokens
    assert_eq!(
        erc20_chain0.balanceOf(env.eoa.address()).call().await?,
        initial_user_balance_chain0 - transfer_amount,
        "User should have transferred tokens on chain 0"
    );
    assert_eq!(
        erc20_chain0.balanceOf(recipient).call().await?,
        transfer_amount,
        "Recipient should have received tokens on chain 0"
    );
    assert!(
        erc20_chain1.balanceOf(fee_payer.address).call().await? < initial_fee_payer_balance_chain1,
        "Fee payer should have paid fees on chain 1"
    );

    Ok(())
}
