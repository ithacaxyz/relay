use crate::{
    config::QuoteConfig,
    constants::ETH_ADDRESS,
    error::{IntentError, RelayError},
    types::IERC20,
};
use alloy::{
    primitives::{Address, B256, Log as PrimitivesLog, LogData, U256},
    providers::{Provider, ext::DebugApi},
    rpc::types::{
        BlockId, Log, TransactionRequest,
        simulate::{SimBlock, SimulatePayload},
        state::StateOverride,
        trace::geth::{
            CallConfig, CallFrame, GethDebugTracingCallOptions, GethDebugTracingOptions,
        },
    },
    sol,
    sol_types::{SolEvent, SolValue},
    transports::TransportErrorKind,
};
use alloy_chains::Chain;
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
}

impl<P: Provider> SimulatorContract<P> {
    /// Create a new simulator wrapper
    pub fn new(simulator_address: Address, provider: P, overrides: StateOverride) -> Self {
        Self {
            simulator: Simulator::SimulatorInstance::new(simulator_address, provider),
            overrides,
        }
    }

    /// Simulates the intent.
    pub async fn simulate(
        &self,
        orchestrator_address: Address,
        mock_from: Address,
        intent_encoded: Vec<u8>,
        gas_validation_offset: U256,
    ) -> Result<SimulationExecutionResult, RelayError> {
        let tx_request =
            TransactionRequest::default().from(mock_from).to(*self.simulator.address()).input(
                self.simulator
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
                    .into(),
            );

        // Check chain ID to determine which simulation method to use
        let chain = Chain::from(self.simulator.provider().get_chain_id().await?);

        if chain.is_ethereum()
            || chain.id() == Chain::bsc_mainnet()
            || chain.id() == Chain::bsc_testnet()
            || chain.id() == Chain::optimism_mainnet()
            || chain.id() == Chain::optimism_sepolia()
            || chain.id() == Chain::base_mainnet()
            || chain.id() == Chain::base_sepolia()
        {
            self.with_simulate_v1(tx_request).await
        } else {
            self.with_debug_trace(tx_request).await
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
            .simulate(
                &SimulatePayload::default().extend(simulate_block.clone()).with_trace_transfers(),
            )
            .await?
            .pop()
            .and_then(|mut block| block.calls.pop())
            .ok_or_else(|| TransportErrorKind::custom_str("could not simulate call"))?;

        if !result.status {
            debug!(?result, ?simulate_block, "Unable to simulate intent.");
            return Err(IntentError::intent_revert(result.return_data).into());
        }

        let gas = decode_gas_results(&result.return_data)?;

        Ok(SimulationExecutionResult { gas, logs: result.logs, tx_request })
    }

    async fn with_debug_trace(
        &self,
        tx_request: TransactionRequest,
    ) -> Result<SimulationExecutionResult, RelayError> {
        let trace_options = GethDebugTracingCallOptions {
            block_overrides: None,
            state_overrides: Some(self.overrides.clone()),
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
            debug!(error = ?call_frame.error, reason = ?call_frame.revert_reason, "Unable to simulate intent - call reverted");
            return Err(IntentError::intent_revert(call_frame.output.unwrap_or_default()).into());
        }

        let gas = decode_gas_results(
            call_frame
                .output
                .as_ref()
                .ok_or_else(|| TransportErrorKind::custom_str("no output from simulation"))?,
        )?;

        Ok(SimulationExecutionResult { gas, logs: collect_logs_from_frame(call_frame), tx_request })
    }
}

/// Result from a simulation execution
#[derive(Debug)]
pub struct SimulationExecutionResult {
    /// Gas estimates from the simulation result
    pub gas: GasResults,
    /// Logs collected from the simulation (including ETH transfers as defined on eth_simulateV1)
    pub logs: Vec<Log>,
    /// The transaction request that was simulated
    pub tx_request: TransactionRequest,
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
fn collect_logs_from_frame(root_frame: CallFrame) -> Vec<Log> {
    let mut logs = Vec::with_capacity(32);
    let mut stack = vec![root_frame];

    while let Some(frame) = stack.pop() {
        if frame.error.is_some() || frame.revert_reason.is_some() {
            continue;
        }

        // Add ETH transfer as log if value > 0 (maintains eth_simulateV1 compatibility)
        if let (Some(value), Some(to)) = (frame.value, frame.to)
            && !value.is_zero()
        {
            logs.push(Log {
                inner: PrimitivesLog {
                    address: ETH_ADDRESS,
                    data: LogData::new_unchecked(
                        vec![
                            IERC20::Transfer::SIGNATURE_HASH,
                            B256::left_padding_from(frame.from.as_slice()),
                            B256::left_padding_from(to.as_slice()),
                        ],
                        value.abi_encode().into(),
                    ),
                },
                ..Default::default()
            });
        }

        // extract logs
        for log in frame.logs {
            if let (Some(address), Some(topics)) = (log.address, log.topics)
                && !topics.is_empty()
            {
                logs.push(Log {
                    inner: PrimitivesLog {
                        address,
                        data: LogData::new_unchecked(topics, log.data.unwrap_or_default()),
                    },
                    ..Default::default()
                });
            };
        }

        stack.extend(frame.calls);
    }

    logs
}
