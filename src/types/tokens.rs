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
        function mint(address recipient, uint256 value);
    }
}

sol! {
    #[sol(rpc)]
    #[derive(Debug)]
    interface IERC721 {
        event Transfer(address indexed from, address indexed to, uint256 indexed id);

        function safeTransferFrom(address from, address to, uint256 id);
        function tokenURI(uint256 id) public view virtual returns (string);
        function burn(uint256 id) public virtual;
    }
}
