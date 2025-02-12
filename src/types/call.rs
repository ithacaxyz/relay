//! ERC-7579 types.

use alloy::sol;

sol! {
    /// ERC-7579 call struct.
    #[derive(Debug)]
    struct Call {
        /// The call target.
        address target;
        /// Amount of native value to send to the target.
        uint256 value;
        /// The calldata bytes.
        bytes data;
    }
}
