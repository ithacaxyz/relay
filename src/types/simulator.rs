use crate::config::QuoteConfig;
use alloy::sol;
use serde::{Deserialize, Serialize};

sol! {

    /// For returning the gas used and the error from a simulation.
    ///
    /// - `gCombined` is the recommendation for `gCombined` in the Intent.
    /// - `gUsed` is the amount of gas that has definitely been used by the Intent.
    #[derive(Debug)]
    struct SimulationResult {
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
