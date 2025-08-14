//! Helpers for Arb fee estimation.

use alloy::{
    primitives::{Address, address},
    sol,
};

/// Address of the Arbitrum [NodeInterface](https://github.com/OffchainLabs/nitro-contracts/blob/master/src/node-interface/NodeInterface.sol).
///
/// Note: This contract doesn't exist on-chain. Instead it is a virtual interface accessible at that
/// address
pub const NODE_INTERFACE_ADDRESS: Address = address!("0x00000000000000000000000000000000000000C8");

sol! {
    #[sol(rpc)]
    #[derive(Debug)]
    contract ArbNodeInterface {
        /// Estimates a transaction's l1 costs.
        ///
        /// Use eth_call to call.
        /// This method is similar to gasEstimateComponents, but doesn't include the l2 component
        /// so that the l1 component can be known even when the tx may fail.
        /// This method also doesn't pad the estimate as gas estimation normally does.
        /// If using this value to submit a transaction, we'd recommend first padding it by 10%.
        ///
        /// # Arguments
        ///
        /// * `data` - the tx's __calldata__. Everything else like "From" and "Gas" are copied over
        /// * `to` - the tx's "To" (ignored when contractCreation is true)
        /// * `contractCreation` - whether "To" is omitted
        ///
        /// # Returns
        ///
        /// * `gasEstimateForL1` - an estimate of the amount of gas needed for the l1 component of this tx
        /// * `baseFee` - the l2 base fee
        /// * `l1BaseFeeEstimate` - ArbOS's l1 estimate of the l1 base fee
        ///
        /// Note: ``
        ///
        /// See also: <https://github.com/OffchainLabs/nitro-contracts/blob/0b8c04e8f5f66fe6678a4f53aa15f23da417260e/src/node-interface/NodeInterface.sol#L113C1-L120C87>
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{
        hex,
        providers::{Provider, ProviderBuilder},
    };

    #[tokio::test]
    async fn test_arb_gas_estimate_l1() {
        let provider =
            ProviderBuilder::new().connect("https://arb1.arbitrum.io/rpc").await.unwrap().erased();

        let calldata = hex!("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        let estimate = ArbNodeInterface::new(NODE_INTERFACE_ADDRESS, provider)
            .gasEstimateL1Component(Address::ZERO, false, calldata.into())
            .call()
            .await
            .unwrap();

        assert!(estimate.gasEstimateForL1 > 0);
    }
}
