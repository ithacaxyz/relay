use alloy::sol;

sol! {
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
}
