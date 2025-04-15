//! Helpers for OP fee estimation.

use alloy::{
    primitives::{Address, address},
    sol,
};

/// Address of the L1Block contract.
pub const OP_FEE_ORACLE_CONTRACT: Address = address!("0x420000000000000000000000000000000000000F");

sol! {
    #[sol(rpc)]
    /// Computes the L1 portion of the fee based on the provided encoded transaction.
    contract OpL1FeeOracle {
        function getL1Fee(bytes memory _data) external view returns (uint256);
    }
}
