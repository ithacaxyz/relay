use alloy::primitives::{Address, U256};
use serde::{Deserialize, Serialize};

use crate::types::{
    CallPermission,
    IthacaAccount::{SpendInfo, SpendPeriod},
};

/// Represents key permissions.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "type")]
pub enum Permission {
    /// Call permission.
    #[serde(rename = "call")]
    Call(CallPermission),
    /// Spend permission.
    #[serde(rename = "spend")]
    Spend(SpendPermission),
}

impl From<CallPermission> for Permission {
    fn from(perm: CallPermission) -> Self {
        Permission::Call(perm)
    }
}

impl From<SpendPermission> for Permission {
    fn from(perm: SpendPermission) -> Self {
        Permission::Spend(perm)
    }
}

/// Represents spend permissions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SpendPermission {
    /// The spending limit.
    pub limit: U256,
    /// The spending period.
    pub period: SpendPeriod,
    /// The token address.
    #[serde(default)]
    pub token: Address,
}

impl From<SpendInfo> for SpendPermission {
    fn from(permission: SpendInfo) -> Self {
        Self { limit: permission.limit, period: permission.period, token: permission.token }
    }
}

#[cfg(test)]
mod tests {
    use crate::types::CallPermission;
    use alloy::primitives::{Address, fixed_bytes};

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
