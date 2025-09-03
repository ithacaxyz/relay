use crate::{
    config::{QuoteConfig, SimMode},
    constants::SIMULATEV1_NATIVE_ADDRESS,
    error::{IntentError, RelayError},
    types::{IERC20, generate_cast_call_command},
};
use alloy::{
    primitives::{Address, B256, BlockNumber, Log, U256},
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
    sol_types::{SolCall, SolEvent, SolValue},
    transports::TransportErrorKind,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, trace};

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
}

impl<P: Provider> SimulatorContract<P> {
    /// Create a new simulator wrapper
    pub fn new(
        simulator_address: Address,
        provider: P,
        overrides: StateOverride,
        sim_mode: SimMode,
    ) -> Self {
        Self {
            simulator: Simulator::SimulatorInstance::new(simulator_address, provider),
            overrides,
            sim_mode,
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
        intent_encoded: Vec<u8>,
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
                intent_encoded.into(),
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
                    intent_encoded.into(),
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

        // check how to simulate
        let result = if self.sim_mode.is_simulate_v1() {
            self.with_simulate_v1(&tx_request).await
        } else {
            self.with_debug_trace(&tx_request).await
        };

        // If simulation failed, log the cast call command for debugging
        if let Err(ref e) = result {
            error!(error = ?e, cast_call = %generate_cast_call_command(&tx_request, &self.overrides), "prepareCalls simulation failed");
        }

        result
    }

    async fn with_simulate_v1(
        &self,
        tx_request: &TransactionRequest,
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

        let (gas, block_number) = decode_aggregate_result(&result.return_data)?;

        Ok(SimulationExecutionResult {
            gas,
            logs: result.logs.into_iter().map(|l| l.into_inner()).collect(),
            tx_request: tx_request.clone(),
            block_number,
        })
    }

    async fn with_debug_trace(
        &self,
        tx_request: &TransactionRequest,
    ) -> Result<SimulationExecutionResult, RelayError> {
        let trace_options = GethDebugTracingCallOptions {
            block_overrides: None,
            state_overrides: Some(self.overrides.clone()),
            // Enable log collection to capture all asset transfers emitted during simulation
            tracing_options: GethDebugTracingOptions::call_tracer(CallConfig::default().with_log()),
        };

        trace!(?tx_request, ?trace_options, "simulating intent with debug_traceCall");

        let call_frame = self
            .simulator
            .provider()
            .debug_trace_call_callframe(tx_request.clone(), BlockId::latest(), trace_options)
            .await
            .map_err(|e| TransportErrorKind::custom_str(&format!("debug_traceCall failed: {e}")))?;

        if call_frame.error.is_some() || call_frame.revert_reason.is_some() {
            debug!(reason = ?call_frame.revert_reason, "Unable to simulate intent - call reverted");
            return Err(IntentError::intent_revert(call_frame.output.unwrap_or_default()).into());
        }

        let (gas, block_number) = decode_aggregate_result(
            call_frame
                .output
                .as_ref()
                .ok_or_else(|| TransportErrorKind::custom_str("no output from simulation"))?,
        )?;

        Ok(SimulationExecutionResult {
            gas,
            logs: collect_logs_from_frame(call_frame),
            tx_request: tx_request.clone(),
            block_number,
        })
    }
}

/// Result from a simulation execution
#[derive(Debug)]
pub struct SimulationExecutionResult {
    /// Gas estimates from the simulation result
    pub gas: GasResults,
    /// Logs with topics collected from the simulation (including ETH transfers as defined on
    /// eth_simulateV1)
    pub logs: Vec<Log>,
    /// The transaction request that was simulated
    pub tx_request: TransactionRequest,
    /// Block number the simulation was executed against
    pub block_number: u64,
}

/// Decodes the tryBlockAndAggregate response to extract gas results and block number.
fn decode_aggregate_result(output: &[u8]) -> Result<(GasResults, BlockNumber), RelayError> {
    let decoded = tryBlockAndAggregateCall::abi_decode_returns(output).map_err(|e| {
        TransportErrorKind::custom_str(&format!(
            "Failed to decode tryBlockAndAggregate result: {e}"
        ))
    })?;

    let block_number = decoded.blockNumber.to::<u64>();

    if decoded.returnData.is_empty() {
        return Err(TransportErrorKind::custom_str("no return data from simulation").into());
    }

    // Check if the call was successful
    if !decoded.returnData[0].success {
        return Err(IntentError::intent_revert(decoded.returnData[0].returnData.clone()).into());
    }

    let gas = decode_gas_results(&decoded.returnData[0].returnData)?;

    Ok((gas, block_number))
}

fn decode_gas_results(output: &[u8]) -> Result<GasResults, RelayError> {
    GasResults::abi_decode(output).map_err(|e| {
        TransportErrorKind::custom_str(&format!(
            "could not decode intent simulation return data: {e}"
        ))
        .into()
    })
}

/// Collect logs from non-reverting calls, including ETH transfers as logs similarly to
/// eth_simulateV1.
///
/// Only logs with topics are collected.
fn collect_logs_from_frame(root_frame: CallFrame) -> Vec<Log> {
    let mut logs = Vec::with_capacity(32);
    let mut stack = vec![root_frame];

    while let Some(frame) = stack.pop() {
        if frame.error.is_some() || frame.revert_reason.is_some() {
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
        for log in frame.logs {
            if let (Some(address), Some(topics)) = (log.address, log.topics)
                && !topics.is_empty()
            {
                logs.push(Log::new_unchecked(address, topics, log.data.unwrap_or_default()));
            };
        }

        stack.extend(frame.calls.into_iter().rev());
    }

    logs
}
