//! Helpers for Arb fee estimation.

use alloy::{
    primitives::{Address, address},
    sol,
};

/// Address of the Arbitrum [NodeInterface](https://github.com/OffchainLabs/nitro-contracts/blob/master/src/node-interface/NodeInterface.sol) contract.
///
/// Note: This contract doesn't exist on-chain. Instead it is a virtual interface accessible at that
/// address
pub const ARB_NODE_INTERFACE_ADDRESS: Address =
    address!("0x00000000000000000000000000000000000000C8");

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
        /// * `gasEstimateForL1` - an estimate of the amount of l2 gas needed for the l1 component of this tx
        /// * `baseFee` - the l2 base fee
        /// * `l1BaseFeeEstimate` - ArbOS's l1 estimate of the l1 base fee
        ///
        /// ## What is the `gasEstimateForL1`
        ///
        /// The `gasEstimateForL1` field is calculated during estimation in the following way - first, the poster data
        /// is calculated with `PosterDataCost`, which internally calls `PosterDataInfo` in gas
        /// estimation:
        /// * <https://github.com/OffchainLabs/nitro/blob/e1671079c5a563d46791cffe68998ddab0cf5823/execution/nodeInterface/NodeInterface.go#L599>
        /// * <https://github.com/OffchainLabs/nitro/blob/e1671079c5a563d46791cffe68998ddab0cf5823/arbos/l1pricing/l1pricing.go#L539>
        ///
        /// This `PosterDataInfo` method calculates `calldata bytes * price per calldata`, which in
        /// the arbitrum docs is referred to by this equation:
        /// ```
        /// L1 Estimated Cost (L1C) = L1 price per byte of data (L1P) * Size of data to be posted in bytes (L1S)
        /// ```
        /// See:
        /// <https://docs.arbitrum.io/build-decentralized-apps/how-to-estimate-gas#breaking-down-the-formula>
        ///
        /// The result of this function is then passed to `GetPosterGas`:
        /// * <https://github.com/OffchainLabs/nitro/blob/d6c96a58bea62fe76b9a74cb8d84b51ae6e9845c/execution/nodeInterface/NodeInterface.go#L610-L611>
        /// * <https://github.com/OffchainLabs/nitro/blob/e1671079c5a563d46791cffe68998ddab0cf5823/arbos/tx_processor.go#L414-L433>
        ///
        /// Which divides the value by essentially the adjusted l2 base fee:
        /// * <https://github.com/OffchainLabs/nitro/blob/e1671079c5a563d46791cffe68998ddab0cf5823/arbos/tx_processor.go#L432>
        ///
        /// The arbitrum docs refer to "L2 Gas Price (P)" as the `baseFee` part of this response:
        /// > P (L2 Gas Price) ⇒ Price to pay for each gas unit. It starts at 0.01 gwei on Arbitrum
        /// > One (0.01 gwei on Arbitrum Nova) and can increase depending on the demand for network
        /// > resources.
        /// > * Call `NodeInterface.GasEstimateComponents()` and get the third element, `baseFee`.
        ///
        /// To calculate the extra gas that should be added to the gas limit, we need to know the
        /// value of this "buffer":
        /// ```
        /// Extra Buffer (B) = L1 Estimated Cost (L1C) / L2 Gas Price (P)
        /// ```
        /// So the `gasEstimateForL1` should refer to the "Extra Buffer" that should be added to the
        /// gas limit in the docs.
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
        let estimate = ArbNodeInterface::new(ARB_NODE_INTERFACE_ADDRESS, provider)
            .gasEstimateL1Component(Address::ZERO, false, calldata.into())
            .call()
            .await
            .unwrap();

        assert!(estimate.gasEstimateForL1 > 0);
    }
}
