use alloy::sol;

sol! {
    #[sol(rpc)]
    #[derive(Debug)]
    contract Simulator {
        function simulateV1Logs(
            address ep,
            bool isPrePayment,
            uint256 paymentPerGas,
            uint256 combinedGasIncrement,
            bytes calldata encodedUserOp
        ) public payable virtual returns (uint256 gasUsed, uint256 combinedGas);
    }
}
