use alloy::sol;
use serde::{Deserialize, Serialize};

sol! {

    /// For returning the gas used and the error from a simulation.
    ///
    /// - `gCombined` is the recommendation for `gCombined` in the UserOp.
    /// - `gUsed` is the amount of gas that has definitely been used by the UserOp.
    struct SimulationResult {
        uint256 gUsed;
        uint256 gCombined;
    }

    #[sol(rpc)]
    #[derive(Debug)]
    contract Simulator {
        function simulateV1Logs(
            address ep,
            bool isPrePayment,
            uint256 paymentPerGas,
            uint256 combinedGasIncrement,
            uint256 combinedGasVerificationOffset,
            bytes calldata encodedUserOp
        ) public payable virtual returns (uint256 gasUsed, uint256 combinedGas);
    }
}

/// A gas estimate result for a [`UserOp`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasEstimate {
    /// The recommended gas limit for the transaction.
    #[serde(with = "alloy::serde::quantity")]
    pub tx: u64,
    /// The recommended gas limit for the [`UserOp`].
    #[serde(with = "alloy::serde::quantity")]
    pub op: u64,
}

impl GasEstimate {
    /// Returns a [`GasEstimate`] calculated from the combined gas returned by the simulator
    /// function, plus any extra buffer.
    ///
    /// The recommended transaction gas is calculated according to the contracts recommendation: [https://github.com/ithacaxyz/account/blob/feffa280d5de487223e43a69126f5b6b3d99a10a/test/SimulateExecute.t.sol#L205-L206]
    pub fn from_combined_gas(combined_gas: u64, tx_gas_buffer: u64) -> Self {
        Self { tx: (((combined_gas + 110_000) * 64) / 63) + tx_gas_buffer, op: combined_gas }
    }
}
