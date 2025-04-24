use alloy::sol;

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
