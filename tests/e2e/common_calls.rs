use super::MockErc20;
use alloy::{
    primitives::{Address, U256},
    sol_types::SolCall,
};
use relay::types::{
    Call,
    Delegation::{self, SpendPeriod},
    Key,
};

/// ERC20 transfer call.
pub fn transfer(erc20: Address, recipient: Address, amount: U256) -> Call {
    Call {
        target: erc20,
        value: U256::ZERO,
        data: MockErc20::transferCall { recipient, amount }.abi_encode().into(),
    }
}

/// ERC20 mint call.
pub fn mint(erc20: Address, a: Address, val: U256) -> Call {
    Call {
        target: erc20,
        value: U256::ZERO,
        data: MockErc20::mintCall { a, val }.abi_encode().into(),
    }
}

/// Set a daily spend limit.
pub fn daily_limit(token: Address, limit: U256, key: &Key) -> Call {
    Call {
        target: Address::ZERO,
        value: U256::ZERO,
        data: Delegation::setSpendLimitCall {
            keyHash: key.key_hash(),
            token,
            period: SpendPeriod::Day,
            limit,
        }
        .abi_encode()
        .into(),
    }
}
