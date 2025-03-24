use super::MockErc20;
use alloy::{
    primitives::{Address, U256, bytes},
    sol_types::SolCall,
};
use relay::types::{Call, Delegation::SpendPeriod, Key};

/// Native transfer value call.
pub fn transfer_native(recipient: Address, amount: U256) -> Call {
    Call { target: recipient, value: amount, data: bytes!("") }
}

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
    Call::set_spend_limit(key.key_hash(), token, SpendPeriod::Day, limit)
}
