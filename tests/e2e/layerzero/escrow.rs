//! LayerZero escrow contract tests
//!
//! This module tests cross-chain token transfers using LayerZero escrow contracts.
//! It includes tests for both manual and automatic message delivery scenarios.
//!
//! ## Test Scenarios
//!
//! - **Manual Delivery**: Tests where LayerZero messages are manually delivered by simulating the
//!   executor and verifier roles
//! - **Automatic Delivery**: Tests using the LayerZero relayer that automatically monitors and
//!   delivers cross-chain messages

use super::{
    LayerZeroEnvironment, OptionsBuilder,
    interfaces::IMockEscrow,
    utils::{compute_guid, create_origin, deliver_layerzero_message},
};
use crate::e2e::{
    environment::{Environment, mint_erc20s},
    send_impersonated_tx,
};
use alloy::{
    network::Ethereum,
    primitives::{Address, Bytes, U256},
    providers::{Provider, ext::AnvilApi},
    sol_types::SolValue,
};
use eyre::Result;
use futures_util::try_join;
use relay::types::IERC20;
use tokio::time::{Duration, sleep};

/// Tests LayerZero escrow functionality with automatic message delivery via relayer
///
/// This test:
/// 1. Sets up a multi-chain environment with LayerZero endpoints
/// 2. Starts the LayerZero relayer for automatic message monitoring
/// 3. Locks tokens on chain 1
/// 4. Waits for the relayer to automatically deliver the message
/// 5. Verifies tokens are unlocked on chain 2
///
/// This test demonstrates the full automated cross-chain flow.
#[tokio::test]
async fn test_multichain_layerzero_escrow_with_automatic_delivery() -> Result<()> {
    let env = Environment::setup_multi_chain_with_layerzero(2).await?;
    let ctx = setup_test_context(&env).await?;

    // Start LayerZero relayer using the new integrated method
    let (_relayer, _handles) = env.start_layerzero_relayer().await?;

    // Setup tokens and balances
    setup_test_balances(&env, &ctx).await?;

    // Check Bob's balance is zero
    let token_contract2 = IERC20::new(ctx.token, env.provider_for(1));
    let bob_balance = token_contract2.balanceOf(ctx.bob).call().await?;
    assert_eq!(bob_balance, U256::ZERO, "Bob should have zero balance before delivery");

    // Execute token lock
    let (fee, options) = prepare_layerzero_transaction(env.provider(), &ctx).await?;
    execute_token_lock(env.provider(), &ctx, fee, options).await?;

    // Wait for automatic delivery (relayer may deliver immediately)
    wait_for_automatic_delivery(env.provider_for(1), &ctx).await?;

    // Check Bob received the tokens on chain 2
    let token_contract2 = IERC20::new(ctx.token, env.provider_for(1));
    let bob_balance = token_contract2.balanceOf(ctx.bob).call().await?;
    assert_eq!(bob_balance, ctx.amount, "Bob should have received the tokens");

    Ok(())
}

/// Tests LayerZero escrow functionality with manual message delivery
#[tokio::test]
async fn test_multichain_layerzero_escrow_with_manual_delivery() -> Result<()> {
    let env = Environment::setup_multi_chain_with_layerzero(2).await?;
    let ctx = setup_test_context(&env).await?;

    // Setup tokens and balances
    setup_test_balances(&env, &ctx).await?;

    // Execute token lock
    let (fee, options) = prepare_layerzero_transaction(env.provider(), &ctx).await?;
    execute_token_lock(env.provider(), &ctx, fee, options).await?;

    // Verify initial state
    verify_lock_state(env.provider(), env.provider_for(1), &ctx).await?;

    // Deliver message and verify final state
    deliver_and_verify_message(&env, &ctx).await?;

    Ok(())
}

// Test helper functions and types

/// Test constants
mod test_constants {
    pub const EXECUTOR_GAS: u128 = 200_000;
    pub const ALICE_ADDRESS: [u8; 20] = [1u8; 20];
    pub const BOB_ADDRESS: [u8; 20] = [2u8; 20];
    pub const TEST_AMOUNT: u64 = 1000;
    pub const ALICE_BALANCE: u64 = 10_000_000_000_000_000_000; // 10 ETH
}

use test_constants::*;

/// Test context containing addresses and configuration
struct TestContext {
    pub alice: Address,
    pub bob: Address,
    pub token: Address,
    pub amount: U256,
    pub escrow1: Address,
    pub escrow2: Address,
    pub endpoint2: Address,
    pub src_eid: u32,
    pub dst_eid: u32,
}

/// Sets up test context with addresses and providers
async fn setup_test_context(env: &Environment) -> Result<TestContext> {
    let lz_config = env.settlement.layerzero.as_ref().expect(
        "LayerZero not configured. Use setup_multi_chain_with_layerzero() to enable LayerZero.",
    );

    Ok(TestContext {
        alice: Address::from(ALICE_ADDRESS),
        bob: Address::from(BOB_ADDRESS),
        token: env.erc20,
        amount: U256::from(TEST_AMOUNT),
        escrow1: lz_config.escrows[0],
        escrow2: lz_config.escrows[1],
        endpoint2: lz_config.endpoints[1],
        src_eid: lz_config.eids[0],
        dst_eid: lz_config.eids[1],
    })
}

/// Sets up initial token balances for test accounts
///
/// - Funds Alice with ETH and ERC20 tokens
/// - Ensures Bob starts with no tokens
/// - Verifies initial balances are correct
async fn setup_test_balances(env: &Environment, ctx: &TestContext) -> Result<()> {
    let token = [ctx.token];
    let alice = [ctx.alice];
    let escrow2 = [ctx.escrow2];

    try_join!(
        mint_erc20s(&token, &alice, env.provider_for(0)),
        mint_erc20s(&token, &escrow2, env.provider_for(1)),
        async {
            env.provider_for(0)
                .anvil_set_balance(ctx.alice, U256::from(ALICE_BALANCE))
                .await
                .map_err(Into::into)
        }
    )?;

    Ok(())
}

/// Prepares LayerZero transaction parameters
async fn prepare_layerzero_transaction<P: Provider + AnvilApi<Ethereum>>(
    provider: &P,
    ctx: &TestContext,
) -> Result<(U256, Bytes)> {
    // Approve token spending
    approve_token_spending(provider, ctx.token, ctx.alice, ctx.escrow1, ctx.amount).await?;

    // Build options and quote fee
    let options = OptionsBuilder::new().add_executor_lz_receive_option(EXECUTOR_GAS, 0).build();

    let fee = IMockEscrow::new(ctx.escrow1, provider)
        .quoteLayerZeroFee(ctx.dst_eid, ctx.token, ctx.amount, ctx.bob, options.clone())
        .call()
        .await?;

    Ok((fee.nativeFee, options))
}

/// Approves token spending for the escrow contract
async fn approve_token_spending<P: Provider + AnvilApi<Ethereum>>(
    provider: &P,
    token: Address,
    owner: Address,
    spender: Address,
    amount: U256,
) -> Result<()> {
    send_impersonated_tx(
        provider,
        IERC20::new(token, provider)
            .approve(spender, amount)
            .from(owner)
            .into_transaction_request(),
        None,
    )
    .await
}

/// Executes the token lock transaction
async fn execute_token_lock<P: Provider + AnvilApi<Ethereum>>(
    provider: &P,
    ctx: &TestContext,
    fee: U256,
    options: Bytes,
) -> Result<()> {
    send_impersonated_tx(
        provider,
        IMockEscrow::new(ctx.escrow1, provider)
            .lockTokens(ctx.token, ctx.amount, ctx.dst_eid, ctx.bob, options)
            .from(ctx.alice)
            .value(fee)
            .into_transaction_request(),
        None,
    )
    .await
}

/// Verifies the lock state after token lock
async fn verify_lock_state<P1: Provider, P2: Provider>(
    provider1: &P1,
    provider2: &P2,
    ctx: &TestContext,
) -> Result<()> {
    let escrow = IMockEscrow::new(ctx.escrow1, provider1);
    let token_contract2 = IERC20::new(ctx.token, provider2);

    // Check locked balance and Bob's balance
    let (locked_balance, bob_balance) =
        try_join!(async { escrow.lockedBalances(ctx.token, ctx.alice).call().await }, async {
            token_contract2.balanceOf(ctx.bob).call().await
        })?;

    assert_eq!(locked_balance, ctx.amount, "Incorrect locked balance");
    assert_eq!(bob_balance, U256::ZERO, "Bob should have zero balance before delivery");

    Ok(())
}

/// Delivers the LayerZero message and verifies the final state
async fn deliver_and_verify_message(env: &Environment, ctx: &TestContext) -> Result<()> {
    // Encode transfer data
    let transfer_data =
        SolValue::abi_encode(&(ctx.token, ctx.alice, ctx.bob, ctx.amount, ctx.src_eid));

    // Prepare message delivery
    let origin = create_origin(ctx.src_eid, ctx.escrow1, 1);
    let guid = compute_guid(1, ctx.src_eid, ctx.escrow1, ctx.dst_eid, ctx.escrow2);
    let provider = env.provider_for(1);

    // Deliver the message
    deliver_layerzero_message(
        provider,
        ctx.endpoint2,
        ctx.src_eid,
        &origin,
        ctx.escrow2,
        guid,
        transfer_data.into(),
    )
    .await?;

    // Verify Bob received the tokens
    let token_contract2 = IERC20::new(ctx.token, provider);
    let bob_balance = token_contract2.balanceOf(ctx.bob).call().await?;
    assert_eq!(bob_balance, ctx.amount, "Bob should have received the tokens");

    Ok(())
}

/// Waits for automatic delivery of the LayerZero message
async fn wait_for_automatic_delivery<P: Provider>(provider: &P, ctx: &TestContext) -> Result<()> {
    const MAX_WAIT_SECONDS: u64 = 10;
    const CHECK_INTERVAL_SECS: u64 = 1;

    let token_contract = IERC20::new(ctx.token, provider);

    for attempt in 1..=MAX_WAIT_SECONDS {
        sleep(Duration::from_secs(CHECK_INTERVAL_SECS)).await;

        let bob_balance = token_contract.balanceOf(ctx.bob).call().await?;

        if bob_balance == ctx.amount {
            return Ok(());
        }

        if attempt == MAX_WAIT_SECONDS {
            return Err(eyre::eyre!(
                "Message was not automatically delivered within {} seconds",
                MAX_WAIT_SECONDS
            ));
        }
    }

    unreachable!()
}
