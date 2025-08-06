//! Main simulation framework and coordinator.

use crate::{
    asset::AssetInfoServiceHandle,
    error::{RelayError, SimulationError},
    estimation::types::SimulationResponse,
    types::{
        Account, FeeEstimationContext, Intent, Key, KeyType, KeyWith712Signer, Orchestrator,
        PartialIntent, Transfer, rpc::BalanceOverrides,
    },
};
use alloy::{
    eips::eip7702::constants::EIP7702_DELEGATION_DESIGNATOR,
    primitives::{Address, Bytes, ChainId, U256},
    providers::Provider,
    rpc::types::state::{AccountOverride, StateOverride, StateOverridesBuilder},
    sol_types::SolValue,
};
use tracing::{debug, instrument};

/// Maximum balance for simulation contracts as required by contract.
/// Set to U256::MAX to meet contract requirements for proper simulation.
const SIMULATION_CONTRACT_BALANCE: U256 = U256::MAX;

/// Contract addresses needed for simulation.
#[derive(Debug, Clone, Copy)]
pub struct SimulationContracts {
    /// The simulator contract address.
    pub simulator: Address,
    /// The orchestrator contract address.
    pub orchestrator: Address,
    /// The delegation implementation contract address.
    pub delegation_implementation: Address,
}

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
async fn build_simulation_state_overrides<P: Provider>(
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

/// Simulates intent execution with the given context.
#[instrument(skip_all)]
pub async fn simulate_intent<P: Provider + Clone>(
    provider: &P,
    intent: &PartialIntent,
    context: FeeEstimationContext,
    fee_token_balance: U256,
    contracts: SimulationContracts,
    asset_info: AssetInfoServiceHandle,
) -> Result<SimulationResponse, RelayError> {
    let simulation_balance = fee_token_balance.saturating_add(U256::from(1));
    let params = SimulationOverrideParams {
        simulator_address: contracts.simulator,
        orchestrator_address: contracts.orchestrator,
        eoa: intent.eoa,
        fee_token: context.fee_token,
        fee_token_balance: simulation_balance,
        account_key: &context.account_key,
        key_slot_override: context.key_slot_override,
        authorization_address: context.authorization_address,
        base_overrides: context.state_overrides.clone(),
        balance_overrides: context.balance_overrides.clone(),
    };
    let overrides = build_simulation_state_overrides(provider, params)
        .await
        .map_err(|e| SimulationError::StateOverrideFailed(e.to_string()))?;

    let orchestrator =
        Orchestrator::new(contracts.orchestrator, provider).with_overrides(overrides);

    let mut intent_to_sign =
        build_intent_from_partial(intent, context.fee_token, contracts.delegation_implementation);

    // For simulation purposes we only simulate with a payment of 1 unit of the fee token. This
    // should be enough to simulate the gas cost of paying for the intent for most (if not all)
    // ERC20s.
    //
    // Additionally, we included a balance override of `balance + 1` unit of the fee token,
    // which ensures the simulation never reverts. Whether the user can actually really
    // pay for the intent execution or not is determined later and communicated to the
    // client.
    intent_to_sign.set_legacy_payment_amount(U256::from(1));
    let (asset_diffs, simulation_result) = orchestrator
        .simulate_execute(
            contracts.simulator,
            &intent_to_sign,
            context.account_key.keyType,
            asset_info,
        )
        .await
        .map_err(|e| SimulationError::ExecutionFailed(e.to_string()))?;

    debug!(
        eoa = %intent.eoa,
        gas_combined = %simulation_result.gCombined,
        "Simulation completed"
    );

    Ok(SimulationResponse::new(asset_diffs, simulation_result.gCombined, simulation_result))
}

/// Builds an Intent from a PartialIntent.
fn build_intent_from_partial(
    partial: &PartialIntent,
    fee_token: Address,
    delegation_implementation: Address,
) -> Intent {
    Intent {
        eoa: partial.eoa,
        executionData: partial.execution_data.clone(),
        nonce: partial.nonce,
        payer: partial.payer.unwrap_or_default(),
        paymentToken: fee_token,
        paymentRecipient: Address::ZERO, // Will be set later
        supportedAccountImplementation: delegation_implementation,
        encodedPreCalls: partial
            .pre_calls
            .iter()
            .map(|pre_call| pre_call.abi_encode().into())
            .collect(),
        encodedFundTransfers: partial
            .fund_transfers
            .iter()
            .map(|(token, amount)| Transfer { token: *token, amount: *amount }.abi_encode().into())
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
    provider: &P,
    account: &crate::types::CreatableAccount,
    _chain_id: ChainId,
    simulator_address: Address,
    orchestrator_address: Address,
    delegation_implementation: Address,
    asset_info: AssetInfoServiceHandle,
) -> Result<(), RelayError> {
    let mock_key = KeyWith712Signer::random_admin(KeyType::Secp256k1)
        .map_err(|e| SimulationError::MockKeyFailed(e.to_string()))?
        .ok_or_else(|| {
            SimulationError::MockKeyFailed("Failed to generate Secp256k1 admin key".to_string())
        })?;

    let intent = PartialIntent {
        eoa: account.address,
        execution_data: Bytes::default(),
        nonce: U256::ZERO,
        payer: None,
        pre_calls: vec![],
        fund_transfers: vec![],
    };

    let context = FeeEstimationContext {
        fee_token: Address::ZERO,
        account_key: mock_key.key().clone(),
        authorization_address: Some(account.signed_authorization.address),
        key_slot_override: true,
        intent_kind: crate::types::IntentKind::Single,
        state_overrides: Default::default(),
        balance_overrides: Default::default(),
    };

    let contracts = SimulationContracts {
        simulator: simulator_address,
        orchestrator: orchestrator_address,
        delegation_implementation,
    };

    simulate_intent(provider, &intent, context, U256::ZERO, contracts, asset_info).await?;

    Ok(())
}
