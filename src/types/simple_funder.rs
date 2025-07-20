use alloy::sol;

sol! {
    #[sol(rpc)]
    interface ISimpleFunder {
        function pullGas(uint256 amount) external;
    }
}
