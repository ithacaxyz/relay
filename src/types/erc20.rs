use alloy::sol;

sol! {
    #[sol(rpc)]
    #[derive(Debug)]
    interface IERC20 {
        event Transfer(address indexed from, address indexed to, uint256 amount);

        function decimals() external view returns (uint8);
        function transfer(address to, uint256 amount) external returns (bool);
    }
}
