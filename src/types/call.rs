//! ERC-7579 types.

use alloy::{
    primitives::{Address, B256, FixedBytes, U256},
    sol,
    sol_types::SolCall,
};
use serde::{Deserialize, Serialize};

use super::{
    Delegation::{SpendPeriod, removeSpendLimitCall, setCanExecuteCall, setSpendLimitCall},
    IDelegation::{authorizeCall, revokeCall},
    Key,
};

sol! {
    /// ERC-7579 call struct.
    #[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
    struct Call {
        /// The call target.
        #[serde(rename = "to")]
        address target;
        /// Amount of native value to send to the target.
        uint256 value;
        /// The calldata bytes.
        bytes data;
    }
}

impl Call {
    /// Create a call to authorize a key on `eoa`.
    pub fn authorize(eoa: Address, key: Key) -> Self {
        Self { target: eoa, data: authorizeCall { key }.abi_encode().into(), ..Default::default() }
    }

    /// Create a call to revoke a key on `eoa`.
    pub fn revoke(eoa: Address, key_hash: B256) -> Self {
        Self {
            target: eoa,
            data: revokeCall { keyHash: key_hash }.abi_encode().into(),
            ..Default::default()
        }
    }

    /// Create a call to allow or disallow executing `selector` on `target` for `key_hash`.
    pub fn set_can_execute(
        eoa: Address,
        key_hash: B256,
        target: Address,
        selector: FixedBytes<4>,
        can_execute: bool,
    ) -> Self {
        Self {
            target: eoa,
            data: setCanExecuteCall {
                keyHash: key_hash,
                target,
                fnSel: selector,
                can: can_execute,
            }
            .abi_encode()
            .into(),
            ..Default::default()
        }
    }

    /// Create a call to set the spend limit for `key_hash` on `token` for `period`.
    pub fn set_spend_limit(
        eoa: Address,
        key_hash: B256,
        token: Address,
        period: SpendPeriod,
        limit: U256,
    ) -> Self {
        Self {
            target: eoa,
            data: setSpendLimitCall { keyHash: key_hash, token, period, limit }.abi_encode().into(),
            ..Default::default()
        }
    }

    /// Create a call to remove the spend limit for `key_hash` on `token` for `period`.
    pub fn remove_spend_limit(
        eoa: Address,
        key_hash: B256,
        token: Address,
        period: SpendPeriod,
    ) -> Self {
        Self {
            target: eoa,
            data: removeSpendLimitCall { keyHash: key_hash, token, period }.abi_encode().into(),
            ..Default::default()
        }
    }
}
