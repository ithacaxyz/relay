use alloy::sol;

sol! {
    #[sol(rpc)]
    #[derive(Debug)]
    interface IERC20 {
        event Transfer(address indexed from, address indexed to, uint256 amount);

        function name() external view returns (string);
        function symbol() external view returns (string);
        function decimals() external view returns (uint8);
        function approve(address spender, uint256 amount) external returns (bool);
        function transfer(address to, uint256 amount) external returns (bool);
        function balanceOf(address eoa) external view returns (uint256);
        function allowance(address owner, address spender) external view returns (uint256);
    }
}

sol! {
    #[sol(rpc)]
    #[derive(Debug)]
    interface IERC721 {
        event Transfer(address indexed from, address indexed to, uint256 indexed amount);

        function safeTransferFrom(address from, address to, uint256 id);
    }
}
