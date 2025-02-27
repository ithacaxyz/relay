//! Ithaca Relay ERC-5792 capabilities.

use alloy::primitives::{Address, FixedBytes, U256};
use serde::{Deserialize, Serialize};

use super::{Call, Delegation::SpendPeriod, Key};

/// Represents a key authorization.
///
/// If the key does not exist, it is added to the account, along with the permissions.
///
/// If the key already exists, the permissions are updated.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizeKey {
    /// The key to authorize or modify permissions for.
    #[serde(flatten)]
    key: Key,
    /// The permissions for the key.
    permissions: Permissions,
}

impl AuthorizeKey {
    /// Transform this key authorization into a series of calls.
    ///
    /// The first call is to add the key to the account. It should only be part of the final
    /// [`UserOp`] if the key does not already exist.
    ///
    /// The second set of calls is to add call permissions and spending limits to the key.
    pub fn into_calls(self, eoa: Address) -> (Call, Vec<Call>) {
        let mut calls = Vec::new();

        calls.extend(self.permissions.calls.into_iter().map(|perm| {
            Call::set_can_execute(eoa, self.key.key_hash(), perm.to, perm.selector, true)
        }));
        calls.extend(self.permissions.spend.into_iter().map(|perm| {
            Call::set_spend_limit(eoa, self.key.key_hash(), perm.token, perm.period, perm.limit)
        }));

        (Call::authorize(eoa, self.key), calls)
    }
}

/// Represents key permissions.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Permissions {
    /// Call permissions.
    calls: Vec<CallPermission>,
    /// Spend permissions.
    spend: Vec<SpendPermission>,
}

/// Represents call permissions.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CallPermission {
    /// The selector of the function this permission applies to.
    #[serde(deserialize_with = "crate::serde::fn_selector::deserialize")]
    selector: FixedBytes<4>,
    /// The address of the contract this permission applies to.
    to: Address,
}

/// Represents spend permissions.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SpendPermission {
    /// The spending limit.
    limit: U256,
    /// The spending period.
    period: SpendPeriod,
    /// The token address.
    #[serde(default)]
    token: Address,
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{Address, fixed_bytes};

    use crate::types::capabilities::CallPermission;

    #[test]
    fn deserialize_call_permission() {
        assert_eq!(
            serde_json::from_str::<CallPermission>(
                r#"{
                "to":"0x0000000000000000000000000000000000000000",
                "selector":"transfer(address,uint256)"
            }"#
            )
            .unwrap(),
            CallPermission { to: Address::ZERO, selector: fixed_bytes!("0xa9059cbb") }
        );

        assert_eq!(
            serde_json::from_str::<CallPermission>(
                r#"
                {
                "to":"0x0000000000000000000000000000000000000000",
                "selector":"0xa9059cbb"
            }"#
            )
            .unwrap(),
            CallPermission { to: Address::ZERO, selector: fixed_bytes!("0xa9059cbb") }
        )
    }
}
