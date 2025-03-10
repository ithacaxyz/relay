use alloy::primitives::{Address, FixedBytes, U256};
use serde::{Deserialize, Serialize};

use crate::types::Delegation::SpendPeriod;

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

/// Represents call permissions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CallPermission {
    /// The selector of the function this permission applies to.
    #[serde(deserialize_with = "crate::serde::fn_selector::deserialize")]
    pub selector: FixedBytes<4>,
    /// The address of the contract this permission applies to.
    pub to: Address,
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

#[cfg(test)]
mod tests {
    use alloy::primitives::{Address, fixed_bytes};

    use crate::types::CallPermission;

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
