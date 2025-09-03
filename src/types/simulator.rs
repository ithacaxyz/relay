use std::collections::HashMap;

use crate::{
    config::{QuoteConfig, SimMode},
    constants::SIMULATEV1_NATIVE_ADDRESS,
    error::{ContractErrors::ContractErrorsErrors, IntentError, RelayError},
    types::{
        Asset, AssetType, IERC20, Intent,
        rpc::{BalanceOverride, BalanceOverrides, RequiredAsset},
    },
};
use alloy::{
    primitives::{Address, B256, BlockNumber, Bytes, Log, U256},
    providers::{
        MULTICALL3_ADDRESS, Provider,
        bindings::IMulticall3::{Call, tryBlockAndAggregateCall},
        ext::DebugApi,
    },
    rpc::types::{
        BlockId, TransactionRequest,
        simulate::{SimBlock, SimulatePayload},
        state::StateOverride,
        trace::geth::{
            CallConfig, CallFrame, GethDebugTracingCallOptions, GethDebugTracingOptions,
        },
    },
    sol,
    sol_types::{SolCall, SolEvent, SolInterface, SolValue},
    transports::TransportErrorKind,
};
use futures::future::JoinAll;
use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

sol! {

    /// For returning the gas used and the error from a simulation.
    ///
    /// - `gCombined` is the recommendation for `gCombined` in the Intent.
    /// - `gUsed` is the amount of gas that has definitely been used by the Intent.
    #[derive(Debug)]
    struct GasResults {
        uint256 gUsed;
        uint256 gCombined;
    }

    #[sol(rpc)]
    #[derive(Debug)]
    #[allow(clippy::too_many_arguments)]
    contract Simulator {
        function simulateV1Logs(
            address ep,
            uint8 paymentPerGasPrecision,
            uint256 paymentPerGas,
            uint256 combinedGasIncrement,
            uint256 combinedGasVerificationOffset,
            bytes calldata encodedIntent
        ) public payable virtual returns (uint256 gasUsed, uint256 combinedGas);
    }

    #[sol(rpc)]
    #[derive(Debug)]
    #[allow(clippy::too_many_arguments)]
    contract SimulatorV4 {
        function simulateV1Logs(
            address ep,
            bool isPrePayment,
            uint8 paymentPerGasPrecision,
            uint256 paymentPerGas,
            uint256 combinedGasIncrement,
            uint256 combinedGasVerificationOffset,
            bytes calldata encodedIntent
        ) public payable virtual returns (uint256 gasUsed, uint256 combinedGas);
    }
}

/// A gas estimate result for a [`Intent`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasEstimate {
    /// The recommended gas limit for the transaction.
    #[serde(with = "alloy::serde::quantity")]
    pub tx: u64,
    /// The recommended gas limit for the [`Intent`].
    #[serde(with = "alloy::serde::quantity")]
    pub intent: u64,
}

impl GasEstimate {
    /// Returns a [`GasEstimate`] calculated from the combined gas returned by the simulator
    /// function, plus any extra buffer.
    ///
    /// The recommended transaction gas is calculated according to the contracts recommendation: [https://github.com/ithacaxyz/account/blob/feffa280d5de487223e43a69126f5b6b3d99a10a/test/SimulateExecute.t.sol#L205-L206]
    pub fn from_combined_gas(
        combined_gas: u64,
        intrinsic_gas: u64,
        quote_config: &QuoteConfig,
    ) -> Self {
        let intent = combined_gas + quote_config.intent_buffer();
        Self { tx: (intent + 110_000 + quote_config.tx_buffer()) * 64 / 63 + intrinsic_gas, intent }
    }
}

/// A Simulator contract wrapper.
#[derive(Debug, Clone)]
pub struct SimulatorContract<P: Provider> {
    simulator: Simulator::SimulatorInstance<P>,
    overrides: StateOverride,
    sim_mode: SimMode,
    calculate_asset_deficits: bool,
}

impl<P: Provider> SimulatorContract<P> {
    /// Create a new simulator wrapper
    pub fn new(
        simulator_address: Address,
        provider: P,
        overrides: StateOverride,
        sim_mode: SimMode,
        calculate_asset_deficits: bool,
    ) -> Self {
        Self {
            simulator: Simulator::SimulatorInstance::new(simulator_address, provider),
            overrides,
            sim_mode,
            calculate_asset_deficits,
        }
    }

    /// Simulates the execution of an intent to estimate its gas usage and collect execution logs.
    ///
    /// Returns a `SimulationExecutionResult` containing:
    /// - Gas estimates for the transaction
    /// - All logs emitted during execution
    /// - The transaction request used for simulation
    /// - The block number from aggregate
    pub async fn simulate(
        &self,
        orchestrator_address: Address,
        mock_from: Address,
        intent: &Intent,
        gas_validation_offset: U256,
        orchestrator_version: Option<&semver::Version>,
    ) -> Result<SimulationExecutionResult, RelayError> {
        // whether orchestrator is v4
        let is_v4 =
            orchestrator_version.map(|v| *v < semver::Version::new(0, 5, 0)).unwrap_or(false);

        let simulate_calldata = if is_v4 {
            // Use SimulatorV4 with additional isPrePayment parameter
            SimulatorV4::SimulatorV4Instance::new(
                *self.simulator.address(),
                self.simulator.provider(),
            )
            .simulateV1Logs(
                orchestrator_address,
                true,
                0,
                U256::ZERO,
                U256::from(11_000),
                gas_validation_offset,
                intent.abi_encode().into(),
            )
            .calldata()
            .clone()
        } else {
            self.simulator
                .simulateV1Logs(
                    orchestrator_address,
                    0,
                    U256::ZERO,
                    U256::from(11_000),
                    gas_validation_offset,
                    intent.abi_encode().into(),
                )
                .calldata()
                .clone()
        };

        // Wrap the simulator call in multicall3's tryBlockAndAggregate to get the block number
        let tx_request =
            TransactionRequest::default().from(mock_from).to(MULTICALL3_ADDRESS).input(
                tryBlockAndAggregateCall {
                    requireSuccess: false,
                    calls: vec![Call {
                        target: *self.simulator.address(),
                        callData: simulate_calldata,
                    }],
                }
                .abi_encode()
                .into(),
            );

        // Use `eth_simulateV1` if `sim_mode` allows it and we don't need to calculate asset
        // deficits
        if self.sim_mode.is_simulate_v1() && !self.calculate_asset_deficits {
            self.with_simulate_v1(tx_request).await
        } else {
            self.with_debug_trace(tx_request, intent).await
        }
    }

    async fn with_simulate_v1(
        &self,
        tx_request: TransactionRequest,
    ) -> Result<SimulationExecutionResult, RelayError> {
        let simulate_block = SimBlock::default()
            .call(tx_request.clone())
            .with_state_overrides(self.overrides.clone());

        trace!(?simulate_block, "simulating intent with eth_simulateV1");

        let result = self
            .simulator
            .provider()
            .simulate(&SimulatePayload::default().extend(simulate_block).with_trace_transfers())
            .await?
            .pop()
            .and_then(|mut block| block.calls.pop())
            .ok_or_else(|| TransportErrorKind::custom_str("could not simulate call"))?;

        if !result.status {
            debug!(?result, ?tx_request, "Unable to simulate intent with eth_simulateV1");
            return Err(IntentError::intent_revert(result.return_data).into());
        }

        let (simulation_result, block_number) = decode_aggregate_result(&result.return_data)?;

        let Ok(gas) = simulation_result else {
            return Err(IntentError::intent_revert(simulation_result.unwrap_err()).into());
        };

        Ok(SimulationExecutionResult {
            gas,
            calls: Vec::new(),
            logs: result.logs.into_iter().map(|l| l.into_inner()).collect(),
            tx_request,
            block_number,
            asset_deficits: HashMap::new(),
        })
    }

    async fn with_debug_trace(
        &self,
        tx_request: TransactionRequest,
        intent: &Intent,
    ) -> Result<SimulationExecutionResult, RelayError> {
        let mut overrides = self.overrides.clone();
        let mut asset_deficits: HashMap<Address, U256> = HashMap::new();

        loop {
            let trace_options = GethDebugTracingCallOptions {
                block_overrides: None,
                state_overrides: Some(overrides.clone()),
                // Enable log collection to capture all asset transfers emitted during simulation
                tracing_options: GethDebugTracingOptions::call_tracer(
                    CallConfig::default().with_log(),
                ),
            };

            trace!(?tx_request, ?trace_options, "simulating intent with debug_traceCall");

            let call_frame = self
                .simulator
                .provider()
                .debug_trace_call_callframe(tx_request.clone(), BlockId::latest(), trace_options)
                .await
                .map_err(|e| {
                    TransportErrorKind::custom_str(&format!("debug_traceCall failed: {e}"))
                })?;

            if call_frame.error.is_some() || call_frame.revert_reason.is_some() {
                debug!(reason = ?call_frame.revert_reason, "Unable to simulate intent - call reverted");
                return Err(
                    IntentError::intent_revert(call_frame.output.unwrap_or_default()).into()
                );
            }

            let (simulation_result, block_number) = decode_aggregate_result(
                call_frame
                    .output
                    .as_ref()
                    .ok_or_else(|| TransportErrorKind::custom_str("no output from simulation"))?,
            )?;

            let (calls, logs) = collect_calls_and_logs_from_frame(call_frame);

            let output = match simulation_result {
                // If intent succeeds as is, just return the result
                Ok(gas) => {
                    return Ok(SimulationExecutionResult {
                        gas,
                        calls,
                        logs,
                        tx_request,
                        block_number,
                        asset_deficits,
                    });
                }
                // If intent failed but we are not asked to calculate asset deficits, return the
                // error
                Err(err) if !self.calculate_asset_deficits => {
                    return Err(IntentError::intent_revert(err).into());
                }
                // Otherwise prodceed to figuring out the asset deficit
                Err(output) => output,
            };

            let Some(asset) = self.find_asset_deficit(&calls, *intent.eoa()).await? else {
                // If there's no deficit detected, just return the error
                return Err(IntentError::intent_revert(output).into());
            };

            if asset_deficits.get(&asset.address).is_some_and(|value| *value >= asset.value) {
                // If we've already applied this deficit, return the error
                return Err(IntentError::intent_revert(output).into());
            }

            // Add the balance to the overrides
            let mut balance_override = BalanceOverride::new(AssetType::ERC20);
            balance_override.add_balance(*intent.eoa(), asset.value);

            overrides.extend(
                BalanceOverrides::new(HashMap::from([(asset.address, balance_override)]))
                    .into_state_overrides(self.simulator.provider())
                    .await?,
            );

            asset_deficits.insert(asset.address, asset.value);
        }
    }

    /// Calculates the asset deficit for each account and asset based on calls.
    ///
    /// Supports only ERC-20 tokens.
    async fn find_asset_deficit(
        &self,
        calls: &[CallFrame],
        eoa: Address,
    ) -> Result<Option<RequiredAsset>, RelayError> {
        let mut missing_asset = None;
        let mut required_funds = U256::ZERO;

        let transfers = calls
            .iter()
            .map(|call| self.decode_transfer_from_call(call))
            .collect::<JoinAll<_>>()
            .await;

        // We iterate over all frames in reverse order and find first transfer that failed,
        // assumption is that this transfer is the one causing entire intent to fail.
        //
        // Once the transfer is found, we find all other transfers of the same asset and sum up the
        // amounts to get the minimum required balance for the intent to succeed.
        for (from, _, asset, amount, success) in transfers.into_iter().flatten().rev() {
            if from != eoa {
                continue;
            }

            if missing_asset.is_none() && !success {
                missing_asset = Some(asset);
            } else if Some(asset) != missing_asset {
                continue;
            }

            required_funds += amount;
        }

        Ok(missing_asset
            .map(|asset| RequiredAsset { address: asset.address(), value: required_funds }))
    }

    /// Extracts the asset deficit from a [`CallFrame`], if there's any detected.
    ///
    /// General algorithm is:
    /// 1. Try to decode the call as ERC-20 `transferFrom` first, and `transfer` second.
    /// 2. If decoding succeeded, start checking common ERC-20 ways to fail on insufficient funds.
    async fn decode_transfer_from_call(
        &self,
        call: &CallFrame,
    ) -> Option<(Address, Address, Asset, U256, bool)> {
        let callee = call.to?;

        // Extract sender and amount
        let (asset, from, to, amount) =
            // First try to decode as `transferFrom`, as it's
            // more likely the user is interacting with a
            // contract that tries to pull funds from their
            // wallet
            IERC20::transferFromCall::abi_decode(&call.input)
                    .map(|transfer| (transfer.from, transfer.to, transfer.amount))
                    .or_else(|_| {
                        // Then try to decode as `transfer` in case the user is making a direct
                        // transfer
                        IERC20::transferCall::abi_decode(&call.input)
                            .map(|transfer| (call.from, transfer.to, transfer.amount))
                    }).map(|(from, to, amount)| {
                        (Asset::Token(callee), from, to, amount)
                    })
                    // If both attempts failed, it's not an ERC-20 transfer. We're sure that it's not a
                    // native token transfer either, because tracing of calls with insufficient native
                    // token balance fails with an error.
                    .ok()?;

        // Check if the call is reverted / errored due to insufficient balance. We check through
        // several common ERC-20 implementations, including specialized cases such as USDT.
        if let Some(revert_reason) = &call.revert_reason
            && (
                // OpenZeppelin < 5.0.0
                revert_reason.contains("transfer amount exceeds balance") ||
                // Solmate and other implementations that don't use SafeMath
                revert_reason.contains("arithmetic underflow or overflow")
            )
        {
        }
        // Check common custom contract errors
        else if let Some(error) =
            call.output.as_ref().and_then(|output| ContractErrorsErrors::abi_decode(output).ok())
            && matches!(
                error,
                ContractErrorsErrors::ERC20InsufficientBalance(_) // OpenZeppelin >= 5.0.0
                    | ContractErrorsErrors::InsufficientBalance(_) // Solady
                    | ContractErrorsErrors::ETHTransferFailed(_) // Solady
                    | ContractErrorsErrors::TransferFailed(_) // Solady
                    | ContractErrorsErrors::TransferFromFailed(_) // Solady
            )
        {
        }
        // USDT transfers just revert on not enough allowance or insufficient funds
        else if call.error.is_some()
            // Make sure it's not a revert due to insufficient allowance
            && let Ok(allowance) = IERC20::new(asset.address(), self.simulator.provider()).allowance(from, to).call().await
            && allowance > amount
        {
        } else {
            return Some((from, to, asset, amount, true));
        }

        Some((from, to, asset, amount, false))
    }
}

/// Result from a simulation execution
#[derive(Debug)]
pub struct SimulationExecutionResult {
    /// Gas estimates from the simulation result
    pub gas: GasResults,
    /// Calls collected from the simulation. `calls` and `logs` fields of each [`CallFrame`] are
    /// not populated.
    pub calls: Vec<CallFrame>,
    /// Logs with topics collected from the simulation (including ETH transfers as defined on
    /// eth_simulateV1)
    pub logs: Vec<Log>,
    /// The transaction request that was simulated
    pub tx_request: TransactionRequest,
    /// Block number the simulation was executed against
    pub block_number: u64,
    /// Required funds for the intent to succeed.
    ///
    /// This is a mapping from asset address to the minimum required balance for the intent to
    /// succeed.
    pub asset_deficits: HashMap<Address, U256>,
}

/// Decodes the tryBlockAndAggregate response to extract gas results and block number.
fn decode_aggregate_result(
    output: &[u8],
) -> Result<(Result<GasResults, Bytes>, BlockNumber), RelayError> {
    let mut decoded = tryBlockAndAggregateCall::abi_decode_returns(output).map_err(|e| {
        TransportErrorKind::custom_str(&format!(
            "Failed to decode tryBlockAndAggregate result: {e}"
        ))
    })?;

    let block_number = decoded.blockNumber.to::<u64>();

    let Some(result) = decoded.returnData.pop() else {
        return Err(TransportErrorKind::custom_str("no return data from simulation").into());
    };

    // Check if the call was successful
    if !result.success {
        return Ok((Err(result.returnData), block_number));
    }

    let gas = decode_gas_results(&result.returnData)?;

    Ok((Ok(gas), block_number))
}

fn decode_gas_results(output: &[u8]) -> Result<GasResults, RelayError> {
    GasResults::abi_decode(output).map_err(|e| {
        TransportErrorKind::custom_str(&format!(
            "could not decode intent simulation return data: {e}"
        ))
        .into()
    })
}

/// Collects calls and logs recursively from a given frame.
///
/// 1. All calls, including reverting ones. `logs` and `calls` fields of each [`CallFrame`] are not
///    populated.
/// 1. Logs from non-reverting calls, including ETH transfers as logs similarly to `eth_simulateV1`.
///    Only logs with topics are collected.
fn collect_calls_and_logs_from_frame(root_frame: CallFrame) -> (Vec<CallFrame>, Vec<Log>) {
    let mut calls = Vec::with_capacity(1);
    let mut logs = Vec::with_capacity(32);
    let mut stack = vec![(root_frame, false)];

    while let Some((mut frame, parent_failed)) = stack.pop() {
        if frame.error.is_some() || frame.revert_reason.is_some() || parent_failed {
            stack.extend(frame.calls.drain(..).rev().map(|f| (f, true)));
            calls.push(frame);
            continue;
        }

        // Add ETH transfer as log if value > 0 (maintains eth_simulateV1 compatibility)
        if let Some(value) = frame.value.filter(|v| !v.is_zero() && frame.typ != "DELEGATECALL") {
            logs.push(Log::new_unchecked(
                SIMULATEV1_NATIVE_ADDRESS,
                vec![
                    IERC20::Transfer::SIGNATURE_HASH,
                    B256::left_padding_from(frame.from.as_slice()),
                    B256::left_padding_from(frame.to.unwrap_or_default().as_slice()),
                ],
                value.abi_encode().into(),
            ));
        }

        // extract logs
        for log in frame.logs.drain(..) {
            if let (Some(address), Some(topics)) = (log.address, log.topics)
                && !topics.is_empty()
            {
                logs.push(Log::new_unchecked(address, topics, log.data.unwrap_or_default()));
            };
        }

        stack.extend(frame.calls.drain(..).rev().map(|f| (f, false)));
        calls.push(frame);
    }

    (calls, logs)
}
