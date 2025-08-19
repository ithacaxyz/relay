//! Helpers for Arbitrum fee estimation.

use alloy::{
    primitives::{Address, address},
    sol,
};

/// Address of the NodeInterface contract.
pub const NODE_INTERFACE_CONTRACT: Address = address!("0x00000000000000000000000000000000000000C8");

sol! {
    #[sol(rpc)]
    contract NodeInterface {
        /**
        * @notice Estimates a transaction's l1 costs.
        * @dev Use eth_call to call.
        *      This method is similar to gasEstimateComponents, but doesn't include the l2 component
        *      so that the l1 component can be known even when the tx may fail.
        *      This method also doesn't pad the estimate as gas estimation normally does.
        *      If using this value to submit a transaction, we'd recommend first padding it by 10%.
        * @param data the tx's calldata. Everything else like "From" and "Gas" are copied over
        * @param to the tx's "To" (ignored when contractCreation is true)
        * @param contractCreation whether "To" is omitted
        * @return gasEstimateForL1 an estimate of the amount of gas needed for the l1 component of this tx
        * @return baseFee the l2 base fee
        * @return l1BaseFeeEstimate ArbOS's l1 estimate of the l1 base fee
        */
        function gasEstimateL1Component(
            address to,
            bool contractCreation,
            bytes calldata data
        )
            external
            payable
            returns (uint64 gasEstimateForL1, uint256 baseFee, uint256 l1BaseFeeEstimate);
    }
}
