use alloy::sol;

sol! {
    contract Delegation {
        address public constant ENTRY_POINT;

        /// Returns the nonce salt.
        function nonceSalt() public view virtual returns (uint256);
    }
}
