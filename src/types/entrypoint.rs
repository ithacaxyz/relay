use alloy::sol;

sol! {
    contract EntryPoint {
        /// For returning the gas used and the error from a simulation.
        #[derive(Debug)]
        error SimulationResult(uint256 gUsed, bytes4 err);

        /// Executes a single encoded user operation.
        ///
        /// `encodedUserOp` is given by `abi.encode(userOp)`, where `userOp` is a struct of type `UserOp`.
        /// If sufficient gas is provided, returns an error selector that is non-zero
        /// if there is an error during the payment, verification, and call execution.
        function execute(bytes calldata encodedUserOp)
            public
            payable
            virtual
            nonReentrant
            returns (bytes4 err);

        /// Simulates an execution and reverts with the amount of gas used, and the error selector.
        ///
        /// An error selector of 0 means the call did not revert.
        function simulateExecute(bytes calldata encodedUserOp) public payable virtual;
    }
}
