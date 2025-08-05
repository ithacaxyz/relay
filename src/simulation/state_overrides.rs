//! Simulation state override builder utilities.

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

/// Builder for constructing state overrides for simulation.
#[derive(Debug, Default)]
pub struct SimulationStateBuilder {
    overrides: StateOverridesBuilder,
}

impl SimulationStateBuilder {
    /// Creates a new state override builder with the specified capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self { overrides: StateOverridesBuilder::with_capacity(capacity) }
    }

    /// Adds balance override for simulator address.
    pub fn with_simulator_balance(mut self, simulator: Address) -> Self {
        self.overrides =
            self.overrides.append(simulator, AccountOverride::default().with_balance(U256::MAX));
        self
    }

    /// Adds balance override for orchestrator address.
    pub fn with_orchestrator_balance(mut self, orchestrator: Address) -> Self {
        self.overrides =
            self.overrides.append(orchestrator, AccountOverride::default().with_balance(U256::MAX));
        self
    }

    /// Adds overrides for the EOA account.
    pub fn with_eoa_overrides(
        mut self,
        eoa: Address,
        fee_token: Address,
        fee_token_balance: U256,
        account_key: &Key,
        key_slot_override: bool,
        authorization_address: Option<Address>,
    ) -> Self {
        let mut override_builder = AccountOverride::default();

        // If the fee token is native, override the balance
        if fee_token.is_zero() {
            override_builder = override_builder.with_balance(fee_token_balance);
        }

        // Add key storage slots if needed
        if key_slot_override {
            override_builder = override_builder.with_state_diff(account_key.storage_slots());
        }

        // Add 7702 delegation code if authorization address is provided
        if let Some(addr) = authorization_address {
            let code = Bytes::from([&EIP7702_DELEGATION_DESIGNATOR, addr.as_slice()].concat());
            override_builder = override_builder.with_code(code);
        }

        self.overrides = self.overrides.append(eoa, override_builder);
        self
    }

    /// Extends with existing state overrides.
    pub fn extend(mut self, overrides: StateOverride) -> Self {
        self.overrides = self.overrides.extend(overrides);
        self
    }

    /// Extends with balance overrides for ERC20 tokens.
    pub async fn extend_with_token_balances<P: Provider>(
        mut self,
        provider: &P,
        fee_token: Address,
        eoa: Address,
        fee_token_balance: U256,
        balance_overrides: BalanceOverrides,
    ) -> Result<Self, RelayError> {
        if !fee_token.is_zero() {
            let modified = balance_overrides
                .modify_token(fee_token, |balance| {
                    balance.add_balance(eoa, fee_token_balance);
                })
                .into_state_overrides(provider)
                .await?;

            self.overrides = self.overrides.extend(modified);
        }
        Ok(self)
    }

    /// Builds the final state overrides.
    pub fn build(self) -> StateOverride {
        self.overrides.build()
    }
}

