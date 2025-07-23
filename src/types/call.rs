//! ERC-7579 types.

use alloy::{
    primitives::{Address, B256, Bytes, FixedBytes, U256},
    sol,
    sol_types::SolCall,
};
use serde::{Deserialize, Serialize};

use crate::{
    error::{AuthError, RelayError},
    types::IERC20,
};

use super::{
    IDelegation::{authorizeCall, revokeCall},
    IthacaAccount::{
        SpendPeriod, removeSpendLimitCall, setCanExecuteCall, setSpendLimitCall,
        upgradeProxyAccountCall,
    },
    Key,
};

sol! {
    /// ERC-7579 call struct.
    #[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
    struct Call {
        /// The call target.
        address to;
        /// Amount of native value to send to the target.
        uint256 value;
        /// The calldata bytes.
        bytes data;
    }
}

impl Call {
    /// Creates a self-call with the given data.
    ///
    /// The executor in ERC7821 replaces `address(0)` with `address(this)`, so we can utilize this
    /// fact to construct self-calls, which are useful for e.g. configuring delegated accounts.
    ///
    /// See <https://github.com/Vectorized/solady/blob/c9e079c0ca836dcc52777a1fa7227ef28e3537b3/src/accounts/ERC7821.sol#L237-L239>.
    pub fn self_call(data: Bytes) -> Self {
        Self { to: Address::ZERO, data, ..Default::default() }
    }

    /// Create a call to authorize a key on `eoa`.
    pub fn authorize(key: Key) -> Self {
        Self::self_call(authorizeCall { key }.abi_encode().into())
    }

    /// Create a call to revoke a key on `eoa`.
    pub fn revoke(key_hash: B256) -> Self {
        Self::self_call(revokeCall { keyHash: key_hash }.abi_encode().into())
    }

    /// Create a call to allow or disallow executing `selector` on `target` for `key_hash`.
    pub fn set_can_execute(
        key_hash: B256,
        target: Address,
        selector: FixedBytes<4>,
        can_execute: bool,
    ) -> Self {
        Self::self_call(
            setCanExecuteCall { keyHash: key_hash, target, fnSel: selector, can: can_execute }
                .abi_encode()
                .into(),
        )
    }

    /// Create a call to set the spend limit for `key_hash` on `token` for `period`.
    pub fn set_spend_limit(
        key_hash: B256,
        token: Address,
        period: SpendPeriod,
        limit: U256,
    ) -> Self {
        Self::self_call(
            setSpendLimitCall { keyHash: key_hash, token, period, limit }.abi_encode().into(),
        )
    }

    /// Create a call to remove the spend limit for `key_hash` on `token` for `period`.
    pub fn remove_spend_limit(key_hash: B256, token: Address, period: SpendPeriod) -> Self {
        Self::self_call(
            removeSpendLimitCall { keyHash: key_hash, token, period }.abi_encode().into(),
        )
    }

    /// Whether this call is whitelisted for precalls.
    pub fn is_whitelisted_precall(
        &self,
        account: Address,
        latest_delegation: Address,
    ) -> Result<bool, RelayError> {
        // Selector needs be 4 bytes.
        if self.data.len() < 4 {
            return Ok(false);
        }

        // Target needs to be the EOA.
        if !(self.to == account || self.to == Address::ZERO) {
            return Ok(false);
        }

        // Only accept upgrades to supported delegations
        self.ensure_valid_upgrade(latest_delegation)?;

        Ok(WHITELISTED_SELECTORS.iter().any(|sel| sel == &self.data[..4]))
    }

    /// If call is a [`upgradeProxyAccountCall`], ensures it's upgrading to the latest delegation
    /// address.
    ///
    /// Otherwise, returns error.
    pub fn ensure_valid_upgrade(&self, latest_delegation: Address) -> Result<(), RelayError> {
        if self.data.len() > 4 && self.data[..4] == upgradeProxyAccountCall::SELECTOR {
            let new_delegation = upgradeProxyAccountCall::abi_decode(&self.data)?.newImplementation;

            if latest_delegation != new_delegation {
                return Err(AuthError::InvalidDelegation(new_delegation).into());
            }
        }

        Ok(())
    }

    /// ERC20 transfer call.
    pub fn transfer(erc20: Address, to: Address, amount: U256) -> Self {
        Self {
            to: erc20,
            value: U256::ZERO,
            data: IERC20::transferCall { to, amount }.abi_encode().into(),
        }
    }
}

/// All selectors allowed in precalls.
const WHITELISTED_SELECTORS: [[u8; 4]; 6] = [
    authorizeCall::SELECTOR,
    revokeCall::SELECTOR,
    setCanExecuteCall::SELECTOR,
    setSpendLimitCall::SELECTOR,
    removeSpendLimitCall::SELECTOR,
    upgradeProxyAccountCall::SELECTOR,
];
