//! Simulation state override utilities.

use crate::{
    error::RelayError,
    types::{Key, rpc::BalanceOverrides},
};
use alloy::{
    eips::eip7702::constants::EIP7702_DELEGATION_DESIGNATOR,
    primitives::{Address, Bytes, U256},
    providers::Provider,
    rpc::types::state::{AccountOverride, StateOverride, StateOverridesBuilder},
};

/// Large but bounded balance for simulation contracts (10 million ETH).
/// This prevents unlimited balance exploits while providing enough funds for legitimate simulations.
const SIMULATION_CONTRACT_BALANCE: U256 = U256::from_limbs([0, 0, 2_116_545_850_052_128_256, 0]);

/// Builds simulation state overrides for intent execution.
///
/// This function creates the necessary state overrides for simulation including:
/// - Contract balances for simulator and orchestrator  
/// - EOA overrides for balance, keys, and delegation code
/// - ERC20 token balance overrides
pub async fn build_simulation_state_overrides<P: Provider>(
    provider: &P,
    simulator_address: Address,
    orchestrator_address: Address,
    eoa: Address,
    fee_token: Address,
    fee_token_balance: U256,
    account_key: &Key,
    key_slot_override: bool,
    authorization_address: Option<Address>,
    base_overrides: StateOverride,
    balance_overrides: BalanceOverrides,
) -> Result<StateOverride, RelayError> {
    let mut builder = StateOverridesBuilder::with_capacity(3);

    // Add contract balances
    builder = builder
        .append(simulator_address, AccountOverride::default().with_balance(SIMULATION_CONTRACT_BALANCE))
        .append(orchestrator_address, AccountOverride::default().with_balance(SIMULATION_CONTRACT_BALANCE));

    // Build EOA overrides
    let mut eoa_override = AccountOverride::default();
    
    // Set native balance if fee token is native
    if fee_token.is_zero() {
        eoa_override = eoa_override.with_balance(fee_token_balance);
    }

    // Add key storage slots if needed
    if key_slot_override {
        eoa_override = eoa_override.with_state_diff(account_key.storage_slots());
    }

    // Add EIP-7702 delegation code if provided
    if let Some(addr) = authorization_address {
        let code = Bytes::from([&EIP7702_DELEGATION_DESIGNATOR, addr.as_slice()].concat());
        eoa_override = eoa_override.with_code(code);
    }

    builder = builder.append(eoa, eoa_override);

    // Extend with base overrides
    builder = builder.extend(base_overrides);

    // Add ERC20 balance overrides if needed
    if !fee_token.is_zero() {
        let token_overrides = balance_overrides
            .modify_token(fee_token, |balance| {
                balance.add_balance(eoa, fee_token_balance);
            })
            .into_state_overrides(provider)
            .await?;
        builder = builder.extend(token_overrides);
    }

    Ok(builder.build())
}

