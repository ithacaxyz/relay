//! Helpers for OP Stack fee estimation.

use alloy::{
    primitives::{Address, address},
    sol,
};

/// Address of the GasPriceOracle contract.
pub const GAS_PRICE_ORACLE_CONTRACT: Address =
    address!("0x420000000000000000000000000000000000000F");

sol! {
    #[sol(rpc)]
    contract GasPriceOracle {
        /// Computes the L1 portion of the fee based on the provided unsigned encoded transaction.
        ///
        /// See also: <https://github.com/ethereum-optimism/optimism/blob/8d85a214e50941793c806a731de5ecc0ad065b2f/packages/contracts-bedrock/src/L2/GasPriceOracle.sol#L57-L68>
        function getL1Fee(bytes memory _data) external view returns (uint256);

        /// Returns an upper bound for the L1 fee for a given transaction size. It assumes the worst case of fastlz upper-bound which covers %99.99 txs.
        ///
        /// _unsignedTxSize: Unsigned fully RLP-encoded transaction size to get the L1 fee for.
        ///
        /// Returns the L1 estimated upper-bound fee that should be paid for the tx.
        ///
        /// See also <https://github.com/ethereum-optimism/optimism/blob/8d85a214e50941793c806a731de5ecc0ad065b2f/packages/contracts-bedrock/src/L2/GasPriceOracle.sol#L70-L85>
        ///
        /// This assumes `(_unsignedTxSize + 68) / 255 + 16` is the practical fastlz upper-bound covers %99.99 txs.
        function getL1FeeUpperBound(uint256 _unsignedTxSize) external view returns (uint256);
    }
}
