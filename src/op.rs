//! Helpers for OP fee estimation.

use alloy::{
    primitives::{Address, address},
    sol,
};

/// Address of the GasPriceOracle contract.
pub const OP_FEE_ORACLE_CONTRACT: Address = address!("0x420000000000000000000000000000000000000F");

sol! {
    #[sol(rpc)]
    contract OpL1FeeOracle {
        /// Computes the L1 portion of the fee based on the provided encoded transaction.
        function getL1Fee(bytes memory _data) external view returns (uint256);
    }
}
