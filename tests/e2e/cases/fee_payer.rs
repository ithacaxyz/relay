//! Tests for fee_payer functionality

use crate::e2e::{
    AuthKind, await_calls_status,
    cases::upgrade_account_eagerly,
    environment::{Environment, mint_erc20s},
    eoa::{MockAccount, MockAccountBuilder},
    layerzero::setup::LayerZeroEnvironment,
};
use alloy::{
    primitives::{Address, ChainId, U256},
    providers::ext::AnvilApi,
    sol_types::SolValue,
};
use eyre::Result;
use relay::{
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    types::{
        AssetDiffResponse, Call, DiffDirection, IERC20, KeyType, KeyWith712Signer, Signature,
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

    // Verify asset diffs
    let asset_diffs = &response.capabilities.asset_diff;
    let fee_totals = &response.capabilities.asset_diff.fee_totals;

    // User should have exactly 1 asset diff on main chain (the transfer, no fees)
    assert_single_outgoing_erc20_diff(
        asset_diffs,
        env.chain_id(),
        env.eoa.address(),
        env.erc20,
        Some(transfer_amount),
        AccountType::User,
    );

    // Verify fee totals
    // Should have fee for the main chain only
    let chain_fee = fee_totals.get(&env.chain_id()).expect("Should have fee total for main chain");
    assert!(chain_fee.value > 0.0, "Fee total should be positive on main chain");
    assert_eq!(chain_fee.currency, "usd");

    // Aggregated fee (chain ID 0) should match the single chain fee
    let aggregated_fee = fee_totals.get(&0).expect("Should have aggregated fee total");
    assert_eq!(
        aggregated_fee.value, chain_fee.value,
        "Aggregated fee should equal single chain fee"
    );
    assert_eq!(aggregated_fee.currency, "usd");

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
async fn test_multichain_fee_payer() -> Result<()> {
    // Setup environment with 2 chains for cross-chain fee payer
    // - User on chain 0 (no fees paid)
    // - Fee payer on chain 1: paid fees
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

    // Verify asset diffs
    let asset_diffs = &response.capabilities.asset_diff;
    let fee_totals = &response.capabilities.asset_diff.fee_totals;

    // Chain 0: User has transfer, fee payer has no diffs
    assert_no_asset_diffs(
        asset_diffs,
        env.chain_id_for(0),
        fee_payer.address,
        AccountType::FeePayer,
    );
    assert_single_outgoing_erc20_diff(
        asset_diffs,
        env.chain_id_for(0),
        env.eoa.address(),
        env.erc20,
        Some(transfer_amount),
        AccountType::User,
    );

    // Chain 1: Fee payer pays fees
    assert_single_outgoing_erc20_diff(
        asset_diffs,
        env.chain_id_for(1),
        fee_payer.address,
        env.erc20,
        None, // Non-zero fee amount
        AccountType::FeePayer,
    );

    // Verify fee totals
    // Both chains have fees, but only chain 1 (fee payer) should be in fee_totals
    let chain0_fee = fee_totals.get(&env.chain_id_for(0));
    let chain1_fee =
        fee_totals.get(&env.chain_id_for(1)).expect("Should have fee total for chain 1");

    assert!(chain1_fee.value > 0.0, "Fee total should be positive on chain 1 (fee payer chain)");
    assert_eq!(chain1_fee.currency, "usd");

    // Aggregated fee (chain ID 0) should be sum of all chain fees
    let aggregated_fee = fee_totals.get(&0).expect("Should have aggregated fee total");
    let expected_total = chain0_fee.map(|f| f.value).unwrap_or(0.0) + chain1_fee.value;
    assert_eq!(
        aggregated_fee.value, expected_total,
        "Aggregated fee should equal sum of all chain fees"
    );
    assert_eq!(aggregated_fee.currency, "usd");

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

#[tokio::test(flavor = "multi_thread")]
async fn test_multichain_user_with_cross_chain_fee_payer() -> Result<()> {
    // Setup environment with 3 chains using LayerZero:
    // - Chain 0: User sources tokens (has ERC20)
    // - Chain 1: User destination (needs ERC20)
    // - Chain 2: Fee payer has funds (has ERC20 for fees)
    let env = Environment::setup_with_config(crate::e2e::EnvironmentConfig {
        num_chains: 3,
        use_layerzero: true,
        ..Default::default()
    })
    .await?;
    let main_key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();

    // Start the LayerZero relayer for automatic message delivery
    let (_relayer, _handles) = env.start_layerzero_relayer().await?;

    // Upgrade main EOA on all chains
    upgrade_account_eagerly(&env, &[main_key.to_authorized()], &main_key, AuthKind::Auth).await?;

    // Create fee_payer account with no ERC20 mint
    let fee_payer = MockAccountBuilder::new().no_erc20_mint().build(&env).await?;

    let chain_0_provider = env.provider_for(0);
    let chain_1_provider = env.provider_for(1);
    let chain_2_provider = env.provider_for(2);

    // Give user ERC20 tokens ONLY on chain 0 (source chain)
    mint_erc20s(&[env.erc20], &[env.eoa.address()], chain_0_provider).await?;

    // Ensure user has ZERO balance on chain 1 (destination) to force sourcing from chain 0
    let slot = alloy::contract::StorageSlotFinder::balance_of(
        chain_1_provider,
        env.erc20,
        env.eoa.address(),
    )
    .find_slot()
    .await?
    .unwrap();
    chain_1_provider
        .anvil_set_storage_at(env.erc20, slot.into(), alloy::primitives::B256::ZERO)
        .await?;

    // Give fee_payer ERC20 tokens ONLY on chain 2 (for cross-chain fee payment)
    mint_erc20s(&[env.erc20], &[fee_payer.address], chain_2_provider).await?;

    // Track balances
    let erc20_chain0 = IERC20::IERC20Instance::new(env.erc20, chain_0_provider);
    let erc20_chain1 = IERC20::IERC20Instance::new(env.erc20, chain_1_provider);
    let erc20_chain2 = IERC20::IERC20Instance::new(env.erc20, chain_2_provider);

    let initial_user_balance_chain0 = erc20_chain0.balanceOf(env.eoa.address()).call().await?;
    let initial_fee_payer_balance_chain2 = erc20_chain2.balanceOf(fee_payer.address).call().await?;

    let decimals_chain0 = erc20_chain0.decimals().call().await?;
    let decimals_chain1 = erc20_chain1.decimals().call().await?;

    // Prepare multichain transfer: use tokens from chain 0, transfer on chain 1, fee_payer on chain
    // 2
    let recipient = Address::random();
    let transfer_amount = U256::from(100);

    let response = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            from: Some(env.eoa.address()),
            calls: vec![Call::transfer(env.erc20, recipient, transfer_amount)],
            chain_id: env.chain_id_for(1),
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

    // Verify this is a multichain intent with cross-chain fee payer
    let quote = response.context.quote().expect("Should have quote context");
    assert_eq!(quote.ty().quotes.len(), 2, "Should have 2 user quotes (source + dest)");
    assert!(quote.ty().multi_chain_root.is_some(), "Should have multichain root");
    assert!(quote.ty().fee_payer.is_some(), "Should have cross-chain fee_payer quote");

    let fee_payer_quote = quote.ty().fee_payer.as_ref().unwrap();
    assert_eq!(
        fee_payer_quote.chain_id,
        env.chain_id_for(2),
        "Fee payer should execute on chain 2"
    );

    // Verify fee_payer_digest is present
    assert!(
        response.capabilities.fee_payer_digest.is_some(),
        "Should have fee_payer_digest for signing"
    );

    // Verify asset diffs
    let asset_diffs = &response.capabilities.asset_diff;
    let fee_totals = &response.capabilities.asset_diff.fee_totals;

    // User escrows the transfer amount (in chain 0 decimals)
    let transfer_amount_chain0_decimals =
        relay::rpc::adjust_balance_for_decimals(transfer_amount, decimals_chain1, decimals_chain0);

    // Chain 0: User escrows, fee payer has no diffs
    assert_no_asset_diffs(
        asset_diffs,
        env.chain_id_for(0),
        fee_payer.address,
        AccountType::FeePayer,
    );
    assert_single_outgoing_erc20_diff(
        asset_diffs,
        env.chain_id_for(0),
        env.eoa.address(),
        env.erc20,
        Some(transfer_amount_chain0_decimals),
        AccountType::User,
    );

    // Chain 1: User and fee payer have no diffs (recipient receives tokens)
    assert_no_asset_diffs(
        asset_diffs,
        env.chain_id_for(1),
        fee_payer.address,
        AccountType::FeePayer,
    );
    assert_no_asset_diffs(asset_diffs, env.chain_id_for(1), env.eoa.address(), AccountType::User);

    // Chain 2: Fee payer pays fees
    assert_single_outgoing_erc20_diff(
        asset_diffs,
        env.chain_id_for(2),
        fee_payer.address,
        env.erc20,
        None, // Non-zero fee amount
        AccountType::FeePayer,
    );

    // Verify fee totals
    // All chains may have fees in fee_totals, but only chain 2 (fee payer) should have non-zero
    let chain0_fee = fee_totals.get(&env.chain_id_for(0));
    let chain1_fee = fee_totals.get(&env.chain_id_for(1));
    let chain2_fee =
        fee_totals.get(&env.chain_id_for(2)).expect("Should have fee total for chain 2");

    assert!(chain2_fee.value > 0.0, "Fee total should be positive on chain 2 (fee payer chain)");
    assert_eq!(chain2_fee.currency, "usd");

    // Aggregated fee (chain ID 0) should be sum of all chain fees
    let aggregated_fee = fee_totals.get(&0).expect("Should have aggregated fee total");
    let expected_total = chain0_fee.map(|f| f.value).unwrap_or(0.0)
        + chain1_fee.map(|f| f.value).unwrap_or(0.0)
        + chain2_fee.value;
    assert!(
        (aggregated_fee.value - expected_total).abs() < 1e-10,
        "Aggregated fee should equal sum of all chain fees: {} vs {}",
        aggregated_fee.value,
        expected_total
    );
    assert_eq!(aggregated_fee.currency, "usd");

    // Sign user intent with merkle root
    let user_signature = main_key.sign_payload_hash(response.digest).await?;

    // Sign fee_payer intent with separate digest
    let fee_payer_digest = response.capabilities.fee_payer_digest.unwrap();
    assert!(response.digest != fee_payer_digest, "Digests should be different");
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
    // - User on chain 0: escrowed the transfer amount (no fees paid, fee_payer covers those)
    // - User on chain 1: should be zero (recipient got the tokens)
    // - Fee payer on chain 2: paid transaction fees
    // - Recipient on chain 1: received tokens

    // Adjust transfer amount from chain 1 decimals to chain 0 decimals
    let transfer_amount_chain0_decimals =
        relay::rpc::adjust_balance_for_decimals(transfer_amount, decimals_chain1, decimals_chain0);

    assert_eq!(
        erc20_chain0.balanceOf(env.eoa.address()).call().await?,
        initial_user_balance_chain0 - transfer_amount_chain0_decimals,
        "User should have escrowed exactly the transfer amount on chain 0"
    );
    assert_eq!(
        erc20_chain1.balanceOf(env.eoa.address()).call().await?,
        U256::ZERO,
        "User should have zero on chain 1"
    );
    assert_eq!(
        erc20_chain1.balanceOf(recipient).call().await?,
        transfer_amount,
        "Recipient should have received tokens on chain 1"
    );
    assert!(
        erc20_chain2.balanceOf(fee_payer.address).call().await? < initial_fee_payer_balance_chain2,
        "Fee payer should have paid fees on chain 2"
    );

    Ok(())
}

#[tokio::test]
async fn test_multichain_all_user_balance_with_fee_payer() -> Result<()> {
    // Setup environment with 3 chains using LayerZero:
    // - Chain 0: User has all their ERC20 tokens (sources entire balance via interop)
    // - Chain 1: User transfers to recipient (no tokens here)
    // - Chain 2: Fee payer sponsors all fees
    let env = Environment::setup_with_config(crate::e2e::EnvironmentConfig {
        num_chains: 3,
        use_layerzero: true,
        ..Default::default()
    })
    .await?;

    // Start the LayerZero relayer for automatic message delivery
    let (_relayer, _handles) = env.start_layerzero_relayer().await?;

    let recipient = Address::random();
    let user = MockAccountBuilder::new().build(&env).await?;
    let fee_payer = MockAccountBuilder::new().no_erc20_mint().build(&env).await?;

    let chain_0_provider = env.provider_for(0);
    let chain_1_provider = env.provider_for(1);
    let chain_2_provider = env.provider_for(2);

    // User gets default ERC20 mint on chain 0
    let erc20_chain0 = IERC20::IERC20Instance::new(env.erc20, chain_0_provider);
    let erc20_chain1 = IERC20::IERC20Instance::new(env.erc20, chain_1_provider);
    let initial_user_balance = erc20_chain0.balanceOf(user.address).call().await?;

    // Transfer amount should be in destination chain decimals
    let decimals_chain0 = erc20_chain0.decimals().call().await?;
    let decimals_chain1 = erc20_chain1.decimals().call().await?;
    let transfer_amount = relay::rpc::adjust_balance_for_decimals(
        initial_user_balance,
        decimals_chain0,
        decimals_chain1,
    );

    // Set user's native balance to zero so they can't pay for gas
    chain_0_provider.anvil_set_balance(user.address, U256::ZERO).await?;

    // Give fee_payer ERC20 tokens ONLY on chain 2
    mint_erc20s(&[env.erc20], &[fee_payer.address], chain_2_provider).await?;

    let erc20_chain1 = IERC20::IERC20Instance::new(env.erc20, chain_1_provider);
    let erc20_chain2 = IERC20::IERC20Instance::new(env.erc20, chain_2_provider);

    let initial_fee_payer_balance = erc20_chain2.balanceOf(fee_payer.address).call().await?;

    // Prepare transfer of ALL tokens to chain 1
    let response = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            from: Some(user.address),
            calls: vec![Call::transfer(env.erc20, recipient, transfer_amount)],
            chain_id: env.chain_id_for(1),
            key: Some(user.key.to_call_key()),
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

    // Verify this is a multichain intent with cross-chain fee payer
    let quote = response.context.quote().expect("Should have quote context");
    assert!(quote.ty().multi_chain_root.is_some(), "Should have multichain root");
    assert!(quote.ty().fee_payer.is_some(), "Should have cross-chain fee_payer quote");

    let fee_payer_quote = quote.ty().fee_payer.as_ref().unwrap();
    assert_eq!(
        fee_payer_quote.chain_id,
        env.chain_id_for(2),
        "Fee payer should execute on chain 2"
    );

    // Sign user intent with merkle root
    let user_signature = user.key.sign_payload_hash(response.digest).await?;

    // Sign fee_payer intent
    let fee_payer_digest = response.capabilities.fee_payer_digest.unwrap();
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
            key: Some(user.key.to_call_key()),
        })
        .await?;

    // Verify transaction succeeded
    let status = await_calls_status(&env, send_response.id).await?;
    assert!(status.status.is_confirmed(), "Transaction should succeed: {:?}", status.status);
    assert!(status.capabilities.unwrap().interop_status.unwrap().is_done());

    // Verify final balances:
    // - User on chain 0: should have transferred all tokens (no fees deducted)
    // - Recipient on chain 1: should receive the full transfer amount
    // - Fee payer on chain 2: paid all fees
    assert_eq!(
        erc20_chain0.balanceOf(user.address).call().await?,
        U256::ZERO,
        "User should have transferred all tokens from chain 0"
    );
    assert_eq!(
        erc20_chain1.balanceOf(user.address).call().await?,
        U256::ZERO,
        "User should still have zero on chain 1"
    );
    assert_eq!(
        erc20_chain1.balanceOf(recipient).call().await?,
        transfer_amount,
        "Recipient should have received the full transfer amount on chain 1"
    );
    assert!(
        erc20_chain2.balanceOf(fee_payer.address).call().await? < initial_fee_payer_balance,
        "Fee payer should have paid fees on chain 2"
    );

    Ok(())
}

// Helper types and functions for asset diff assertions

#[derive(Debug, Clone, Copy)]
enum AccountType {
    User,
    FeePayer,
}

impl std::fmt::Display for AccountType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccountType::User => write!(f, "User"),
            AccountType::FeePayer => write!(f, "Fee payer"),
        }
    }
}

/// Helper to get all asset diffs for a specific owner on a chain
fn get_asset_diffs_for_owner(
    asset_diffs: &AssetDiffResponse,
    chain_id: ChainId,
    owner: Address,
) -> Vec<relay::types::AssetDiff> {
    asset_diffs
        .asset_diffs
        .get(&chain_id)
        .map(|chain_diffs| {
            chain_diffs
                .0
                .iter()
                .filter(|(o, _)| *o == owner)
                .flat_map(|(_, diffs)| diffs.iter().cloned())
                .collect()
        })
        .unwrap_or_default()
}

/// Assert that an address has no asset diffs on a specific chain
fn assert_no_asset_diffs(
    asset_diffs: &AssetDiffResponse,
    chain_id: ChainId,
    owner: Address,
    account_type: AccountType,
) {
    let diffs = get_asset_diffs_for_owner(asset_diffs, chain_id, owner);
    assert_eq!(diffs.len(), 0, "{} should have no asset diffs on chain {}", account_type, chain_id);
}

/// Assert that an address has exactly one outgoing ERC20 diff
///
/// If expected_value is Some, asserts exact value. If None, asserts non-zero (for fees).
fn assert_single_outgoing_erc20_diff(
    asset_diffs: &AssetDiffResponse,
    chain_id: ChainId,
    owner: Address,
    token: Address,
    expected_value: Option<U256>,
    account_type: AccountType,
) {
    let diffs = get_asset_diffs_for_owner(asset_diffs, chain_id, owner);
    assert_eq!(
        diffs.len(),
        1,
        "{} should have exactly 1 asset diff on chain {}",
        account_type,
        chain_id
    );

    let diff = &diffs[0];
    assert_eq!(
        diff.address,
        Some(token),
        "{}'s diff should be for the correct token",
        account_type
    );
    assert_eq!(
        diff.direction,
        DiffDirection::Outgoing,
        "{}'s diff should be outgoing",
        account_type
    );

    match expected_value {
        Some(value) => {
            assert_eq!(diff.value, value, "{}'s diff value should match expected", account_type);
        }
        None => {
            assert!(
                diff.value > U256::ZERO,
                "{} should have non-zero value (got {})",
                account_type,
                diff.value
            );
        }
    }
}
