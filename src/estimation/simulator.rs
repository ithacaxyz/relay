//! Simulation logic for intent execution.
//!
//! This module handles:
//! - Intent simulation against the blockchain
//! - Gas usage estimation
//! - State override preparation
//! - Asset difference calculation

use crate::{
    error::RelayError,
    types::{FeeEstimationContext, PartialIntent},
};
use alloy::{
    primitives::{Address, U256},
    providers::Provider,
    rpc::types::state::{AccountOverride, StateOverridesBuilder},
};

/// Builds state overrides for intent simulation.
///
/// This function constructs the necessary state overrides for simulating an intent,
/// including:
/// - Mock signer balance
/// - EOA key storage slots
/// - EIP-7702 delegation code
/// - Fee token balance overrides
pub async fn build_simulation_overrides<P: Provider>(
    intent: &PartialIntent,
    context: &FeeEstimationContext,
    mock_from: Address,
    fee_token_balance: U256,
    provider: &P,
) -> Result<StateOverridesBuilder, RelayError> {
    // Add 1 wei worth of the fee token to ensure the user always has enough to pass the call
    // simulation
    let new_fee_token_balance = fee_token_balance.saturating_add(U256::from(1));

    // mocking key storage for the eoa, and the balance for the mock signer
    let mut overrides = StateOverridesBuilder::with_capacity(2)
        // simulateV1Logs requires it, so the function can only be called under a testing
        // environment
        .append(mock_from, AccountOverride::default().with_balance(U256::MAX))
        .append(
            intent.eoa,
            AccountOverride::default()
                // If the fee token is the native token, we override it
                .with_balance_opt(context.fee_token.is_zero().then_some(new_fee_token_balance))
                .with_state_diff(if context.key_slot_override {
                    context.account_key.storage_slots()
                } else {
                    Default::default()
                })
                // we manually etch the 7702 designator since we do not have a signed auth item
                .with_7702_delegation_designator_opt(context.stored_auth_address()),
        )
        .extend(context.state_overrides.clone());

    // If the fee token is an ERC20, we do a balance override, merging it with the client
    // supplied balance override if necessary.
    if !context.fee_token.is_zero() {
        overrides = overrides.extend(
            context
                .balance_overrides
                .clone()
                .modify_token(context.fee_token, |balance| {
                    balance.add_balance(intent.eoa, new_fee_token_balance);
                })
                .into_state_overrides(provider)
                .await?,
        );
    }

    Ok(overrides)
}
