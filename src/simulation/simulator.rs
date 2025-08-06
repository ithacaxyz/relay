//! Main simulation framework and coordinator.

use crate::{
    asset::AssetInfoServiceHandle,
    error::{RelayError, SimulationError},
    simulation::state_overrides::build_simulation_state_overrides,
    types::{
        Account, AssetDiffs, FeeEstimationContext, Intent, Key, KeyType, KeyWith712Signer,
        Orchestrator, PartialIntent, SimulationResult, Transfer, rpc::BalanceOverrides,
    },
};
use alloy::{
    primitives::{Address, Bytes, ChainId, U256},
    providers::Provider,
    rpc::types::state::StateOverride,
    sol_types::SolValue,
};
use tracing::{debug, instrument};

/// Context required for simulation execution.
#[derive(Debug, Clone)]
pub struct SimulationContext {
    /// The fee token address.
    pub fee_token: Address,
    /// The account key used for signing.
    pub account_key: Key,
    /// Optional authorization address for EIP-7702 delegation.
    pub authorization_address: Option<Address>,
    /// Whether to override key slots in state.
    pub key_slot_override: bool,
    /// State overrides for simulation.
    pub state_overrides: StateOverride,
    /// Balance overrides for simulation.
    pub balance_overrides: BalanceOverrides,
}

impl From<FeeEstimationContext> for SimulationContext {
    fn from(ctx: FeeEstimationContext) -> Self {
        Self {
            fee_token: ctx.fee_token,
            account_key: ctx.account_key,
            authorization_address: ctx.authorization_address,
            key_slot_override: ctx.key_slot_override,
            state_overrides: ctx.state_overrides,
            balance_overrides: ctx.balance_overrides,
        }
    }
}

/// Result of intent simulation.
#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct SimulationOutput {
    /// Asset differences calculated from simulation.
    pub asset_diffs: AssetDiffs,
    /// Gas estimates from simulation.
    pub gas_combined: U256,
    /// Raw simulation result from contract.
    pub simulation_result: SimulationResult,
}

/// Main simulator for intent execution.
#[derive(Debug)]
pub struct IntentSimulator {
    /// Simulator contract address.
    simulator_address: Address,
    /// Orchestrator contract address.
    orchestrator_address: Address,
    /// Asset info service handle.
    asset_info: AssetInfoServiceHandle,
}

impl IntentSimulator {
    /// Creates a new intent simulator.
    pub fn new(
        simulator_address: Address,
        orchestrator_address: Address,
        asset_info: AssetInfoServiceHandle,
    ) -> Self {
        Self { simulator_address, orchestrator_address, asset_info }
    }

    /// Simulates intent execution with the given context.
    #[instrument(skip_all)]
    pub async fn simulate_intent<P: Provider + Clone>(
        &self,
        provider: &P,
        intent: &PartialIntent,
        context: SimulationContext,
        fee_token_balance: U256,
    ) -> Result<SimulationOutput, SimulationError> {
        // Build state overrides for simulation
        let overrides = self
            .build_state_overrides(provider, intent, &context, fee_token_balance)
            .await
            .map_err(|e| SimulationError::StateOverrideFailed(e.to_string()))?;

        // Create account with overrides
        let _account = Account::new(intent.eoa, provider).with_overrides(overrides.clone());

        // Create orchestrator with overrides
        let orchestrator =
            Orchestrator::new(self.orchestrator_address, provider).with_overrides(overrides);

        // Build intent from partial intent
        let mut intent_to_sign = self.build_intent_from_partial(
            intent,
            context.fee_token,
            context.authorization_address.unwrap_or_default(),
        );

        // Set payment amount for simulation
        intent_to_sign.set_legacy_payment_amount(U256::from(1));

        // Execute simulation
        let (asset_diffs, simulation_result) = orchestrator
            .simulate_execute(
                self.simulator_address,
                &intent_to_sign,
                context.account_key.keyType,
                self.asset_info.clone(),
            )
            .await
            .map_err(|e| SimulationError::ExecutionFailed(e.to_string()))?;

        debug!(
            eoa = %intent.eoa,
            gas_combined = %simulation_result.gCombined,
            "Simulation completed"
        );

        Ok(SimulationOutput {
            asset_diffs,
            gas_combined: simulation_result.gCombined,
            simulation_result,
        })
    }

    /// Builds state overrides for simulation.
    async fn build_state_overrides<P: Provider + Clone>(
        &self,
        provider: &P,
        intent: &PartialIntent,
        context: &SimulationContext,
        fee_token_balance: U256,
    ) -> Result<StateOverride, RelayError> {
        // Add 1 to the user's balance to ensure simulation passes
        let simulation_balance = fee_token_balance.saturating_add(U256::from(1));

        // Build state overrides using simplified function
        let params = crate::simulation::state_overrides::SimulationOverrideParams {
            simulator_address: self.simulator_address,
            orchestrator_address: self.orchestrator_address,
            eoa: intent.eoa,
            fee_token: context.fee_token,
            fee_token_balance: simulation_balance,
            account_key: &context.account_key,
            key_slot_override: context.key_slot_override,
            authorization_address: context.authorization_address,
            base_overrides: context.state_overrides.clone(),
            balance_overrides: context.balance_overrides.clone(),
        };
        let overrides = build_simulation_state_overrides(provider, params).await?;

        Ok(overrides)
    }

    /// Builds an Intent from a PartialIntent.
    fn build_intent_from_partial(
        &self,
        partial: &PartialIntent,
        fee_token: Address,
        delegation: Address,
    ) -> Intent {
        Intent {
            eoa: partial.eoa,
            executionData: partial.execution_data.clone(),
            nonce: partial.nonce,
            payer: partial.payer.unwrap_or_default(),
            paymentToken: fee_token,
            paymentRecipient: Address::ZERO, // Will be set later
            supportedAccountImplementation: delegation,
            encodedPreCalls: partial
                .pre_calls
                .iter()
                .map(|pre_call| pre_call.abi_encode().into())
                .collect(),
            encodedFundTransfers: partial
                .fund_transfers
                .iter()
                .map(|(token, amount)| {
                    Transfer { token: *token, amount: *amount }.abi_encode().into()
                })
                .collect(),
            isMultichain: false,
            ..Default::default()
        }
    }

    /// Simulates account initialization.
    ///
    /// Note: This function uses a mock key because during account initialization,
    /// the user doesn't have a real key yet - the account is being created.
    /// This is the only legitimate use of mock keys in production.
    pub async fn simulate_init<P: Provider + Clone>(
        &self,
        provider: &P,
        account: &crate::types::CreatableAccount,
        _chain_id: ChainId,
    ) -> Result<(), SimulationError> {
        // Use mock key for init simulation - this is required because the account
        // is being created and doesn't have a real key yet
        let mock_key = KeyWith712Signer::random_admin(KeyType::Secp256k1)
            .map_err(|e| SimulationError::MockKeyFailed(e.to_string()))?
            .ok_or_else(|| {
                SimulationError::MockKeyFailed("Failed to generate Secp256k1 admin key".to_string())
            })?;

        // Build partial intent for init
        let intent = PartialIntent {
            eoa: account.address,
            execution_data: Bytes::default(),
            nonce: U256::ZERO,
            payer: None,
            pre_calls: vec![],
            fund_transfers: vec![],
        };

        // Create simulation context
        let context = SimulationContext {
            fee_token: Address::ZERO,
            account_key: mock_key.key().clone(),
            authorization_address: Some(account.signed_authorization.address),
            key_slot_override: true,
            state_overrides: Default::default(),
            balance_overrides: Default::default(),
        };

        // Run simulation
        self.simulate_intent(provider, &intent, context, U256::ZERO).await?;

        Ok(())
    }
}
