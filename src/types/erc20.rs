use alloy::sol;

sol! {
    #[sol(rpc)]
    interface IERC20 {
        function decimals() external view returns (uint8);
        function transfer(address to, uint256 amount) external returns (bool);
    }
}
