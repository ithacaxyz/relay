//! Main simulation framework and coordinator.

use crate::{
    asset::AssetInfoServiceHandle,
    error::{KeysError, RelayError, SimulationError},
    estimation::types::SimulationResponse,
    types::{
        Call, CreatableAccount, FeeEstimationContext, Intent, IntentKind, Key, KeyType,
        KeyWith712Signer, Orchestrator, PartialIntent, rpc::BalanceOverrides,
    },
};
use alloy::{
    eips::eip7702::constants::EIP7702_DELEGATION_DESIGNATOR,
    primitives::{Address, B256, Bytes, ChainId, U256},
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
    /// Mock transaction signer address.
    pub mock_from: Address,
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
        )
        .append(params.mock_from, AccountOverride::default().with_balance(U256::MAX));

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
        match params
            .balance_overrides
            .modify_token(params.fee_token, |balance| {
                balance.add_balance(params.eoa, params.fee_token_balance);
            })
            .into_state_overrides(provider)
            .await
        {
            Ok(token_overrides) => {
                builder = builder.extend(token_overrides);
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to create ERC20 balance overrides for token {} in simulation: {}. Continuing without balance override.",
                    params.fee_token,
                    e
                );
                // Continue without balance override for simulation
            }
        }
    }

    Ok(builder.build())
}

/// Simulates intent execution with the given context.
#[instrument(skip_all)]
pub async fn simulate_intent<P: Provider + Clone>(
    provider: &P,
    intent_to_sign: &Intent,
    context: FeeEstimationContext,
    fee_token_balance: U256,
    contracts: SimulationContracts,
    asset_info: AssetInfoServiceHandle,
) -> Result<SimulationResponse, RelayError> {
    // Create a mock transaction signer
    let mock_from = Address::random();
    let simulation_balance = fee_token_balance.saturating_add(U256::from(1));
    let params = SimulationOverrideParams {
        simulator_address: contracts.simulator,
        orchestrator_address: contracts.orchestrator,
        eoa: intent_to_sign.eoa,
        fee_token: context.fee_token,
        fee_token_balance: simulation_balance,
        account_key: &context.account_key,
        key_slot_override: context.key_slot_override,
        authorization_address: context.stored_authorization.as_ref().map(|auth| auth.address),
        base_overrides: context.state_overrides.clone(),
        balance_overrides: context.balance_overrides.clone(),
        mock_from,
    };
    let overrides = build_simulation_state_overrides(provider, params)
        .await
        .map_err(|e| SimulationError::StateOverrideFailed(e.to_string()))?;

    let orchestrator =
        Orchestrator::new(contracts.orchestrator, provider).with_overrides(overrides);

    // For simulation purposes we only simulate with a payment of 1 unit of the fee token. This
    // should be enough to simulate the gas cost of paying for the intent for most (if not all)
    // ERC20s.
    //
    // Additionally, we included a balance override of `balance + 1` unit of the fee token,
    // which ensures the simulation never reverts. Whether the user can actually really
    // pay for the intent execution or not is determined later and communicated to the
    // client.
    let (asset_diffs, simulation_result) = orchestrator
        .simulate_execute(
            mock_from,
            contracts.simulator,
            intent_to_sign,
            asset_info,
            U256::ZERO, // gas_validation_offset
        )
        .await
        .map_err(|e| SimulationError::ExecutionFailed(e.to_string()))?;

    debug!(
        eoa = %intent_to_sign.eoa,
        gas_combined = %simulation_result.gCombined,
        "Simulation completed"
    );

    Ok(SimulationResponse::new(asset_diffs, simulation_result.gCombined, simulation_result))
}

/// Simulates the account initialization call to ensure precall works.
///
/// This function validates that an account initialization precall will execute
/// successfully by running it through the simulation pipeline.
#[instrument(skip_all)]
pub async fn simulate_init<P: Provider + Clone>(
    provider: &P,
    account: &CreatableAccount,
    _chain_id: ChainId,
    contracts: SimulationContracts,
    asset_info: AssetInfoServiceHandle,
) -> Result<(), RelayError> {
    // Create a mock admin key for simulation
    let mock_key = KeyWith712Signer::random_admin(KeyType::Secp256k1)
        .map_err(RelayError::from)
        .and_then(|k| k.ok_or_else(|| RelayError::Keys(KeysError::UnsupportedKeyType)))?;

    // Create a dummy PartialIntent that includes the initialization precall
    let partial_intent = PartialIntent {
        eoa: account.address,
        execution_data: Vec::<Call>::new().abi_encode().into(),
        nonce: U256::from_be_bytes(B256::random().into()) << 64,
        payer: None,
        pre_calls: vec![account.pre_call.clone()],
        fund_transfers: vec![],
    };

    // Create the fee estimation context for simulation
    let context = FeeEstimationContext {
        fee_token: Address::ZERO, // Use native token
        stored_authorization: Some(account.signed_authorization.clone()),
        account_key: mock_key.key().clone(),
        key_slot_override: true,
        intent_kind: IntentKind::Single,
        state_overrides: Default::default(),
        balance_overrides: Default::default(),
    };

    // Build intent for simulation with minimal payment amount
    let mut intent_to_sign = Intent {
        eoa: partial_intent.eoa,
        executionData: partial_intent.execution_data.clone(),
        nonce: partial_intent.nonce,
        payer: partial_intent.payer.unwrap_or_default(),
        paymentToken: Address::ZERO,
        paymentRecipient: Address::ZERO, // Will be set by caller if needed
        supportedAccountImplementation: contracts.delegation_implementation,
        encodedPreCalls: partial_intent
            .pre_calls
            .iter()
            .map(|pre_call| pre_call.abi_encode().into())
            .collect(),
        encodedFundTransfers: partial_intent
            .fund_transfers
            .iter()
            .map(|(token, amount)| {
                crate::types::Transfer { token: *token, amount: *amount }.abi_encode().into()
            })
            .collect(),
        isMultichain: false,
        ..Default::default()
    };

    // Set minimal payment amount for simulation
    intent_to_sign.set_legacy_payment_amount(U256::from(1));

    // Run the simulation to ensure initialization precall works
    simulate_intent(
        provider,
        &intent_to_sign,
        context,
        U256::ZERO, // fee_token_balance (not relevant for init simulation)
        contracts,
        asset_info,
    )
    .await?;

    Ok(())
}
