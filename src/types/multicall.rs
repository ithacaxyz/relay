//! Multicall3 contract interface for batching multiple calls.

use alloy::sol;

sol! {
    /// Represents a single call in a multicall batch
    #[derive(Debug)]
    struct Call3 {
        /// Target contract address
        address target;
        /// Whether to allow this call to fail
        bool allowFailure;
        /// Encoded function call data
        bytes callData;
    }

    /// Result of a single call in aggregate3
    #[derive(Debug)]
    struct Result {
        /// Whether the call was successful
        bool success;
        /// The return data from the call
        bytes returnData;
    }

    /// Execute multiple calls in a single transaction
    function aggregate3(Call3[] calldata calls) public payable returns (Result[] memory returnData);
}
