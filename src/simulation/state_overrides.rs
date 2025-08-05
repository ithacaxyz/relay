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
/// This prevents unlimited balance exploits while providing enough funds for legitimate
/// simulations.
const SIMULATION_CONTRACT_BALANCE: U256 = U256::from_limbs([0, 0, 2_116_545_850_052_128_256, 0]);

/// Parameters for building simulation state overrides.
#[derive(Debug)]
pub struct SimulationOverrideParams<'a> {
    /// The simulator contract address.
    pub simulator_address: Address,
    /// The orchestrator contract address.
    pub orchestrator_address: Address,
    /// The EOA address being simulated.
    pub eoa: Address,
    /// The fee token address.
    pub fee_token: Address,
    /// The fee token balance to set for the EOA.
    pub fee_token_balance: U256,
    /// The account key for storage slot overrides.
    pub account_key: &'a Key,
    /// Whether to override key slots in state.
    pub key_slot_override: bool,
    /// Optional authorization address for EIP-7702 delegation.
    pub authorization_address: Option<Address>,
    /// Base state overrides to extend.
    pub base_overrides: StateOverride,
    /// Balance overrides for ERC20 tokens.
    pub balance_overrides: BalanceOverrides,
}

/// Builds simulation state overrides for intent execution.
///
/// This function creates the necessary state overrides for simulation including:
/// - Contract balances for simulator and orchestrator
/// - EOA overrides for balance, keys, and delegation code
/// - ERC20 token balance overrides
pub async fn build_simulation_state_overrides<P: Provider>(
    provider: &P,
    params: SimulationOverrideParams<'_>,
) -> Result<StateOverride, RelayError> {
    let mut builder = StateOverridesBuilder::with_capacity(3);

    // Add contract balances
    builder = builder
        .append(
            params.simulator_address,
            AccountOverride::default().with_balance(SIMULATION_CONTRACT_BALANCE),
        )
        .append(
            params.orchestrator_address,
            AccountOverride::default().with_balance(SIMULATION_CONTRACT_BALANCE),
        );

    // Build EOA overrides
    let mut eoa_override = AccountOverride::default();

    // Set native balance if fee token is native
    if params.fee_token.is_zero() {
        eoa_override = eoa_override.with_balance(params.fee_token_balance);
    }

    // Add key storage slots if needed
    if params.key_slot_override {
        eoa_override = eoa_override.with_state_diff(params.account_key.storage_slots());
    }

    // Add EIP-7702 delegation code if provided
    if let Some(addr) = params.authorization_address {
        let code = Bytes::from([&EIP7702_DELEGATION_DESIGNATOR, addr.as_slice()].concat());
        eoa_override = eoa_override.with_code(code);
    }

    builder = builder.append(params.eoa, eoa_override);

    // Extend with base overrides
    builder = builder.extend(params.base_overrides);

    // Add ERC20 balance overrides if needed
    if !params.fee_token.is_zero() {
        let token_overrides = params
            .balance_overrides
            .modify_token(params.fee_token, |balance| {
                balance.add_balance(params.eoa, params.fee_token_balance);
            })
            .into_state_overrides(provider)
            .await?;
        builder = builder.extend(token_overrides);
    }

    Ok(builder.build())
}
