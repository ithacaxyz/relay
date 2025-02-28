//! Ithaca Relay ERC-5792 capabilities.

use alloy::primitives::{Address, FixedBytes, U256};
use serde::{Deserialize, Serialize};

use super::{Call, Delegation::SpendPeriod, Key};
use crate::types::U40;

/// Represents a key authorization.
///
/// If the key does not exist, it is added to the account, along with the permissions.
///
/// If the key already exists, the permissions are updated.
#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct AuthorizeKey {
    /// The key to authorize or modify permissions for.
    #[serde(flatten)]
    key: Key,
    /// The permissions for the key.
    permissions: Vec<Permission>,
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

        calls.extend(self.permissions.into_iter().map(|perm| match perm {
            Permission::Call(perm) => {
                Call::set_can_execute(eoa, self.key.key_hash(), perm.to, perm.selector, true)
            }
            Permission::Spend(perm) => {
                Call::set_spend_limit(eoa, self.key.key_hash(), perm.token, perm.period, perm.limit)
            }
        }));

        (Call::authorize(eoa, self.key), calls)
    }
}

// Custom deserializer to enforce key validation rules
impl<'de> Deserialize<'de> for AuthorizeKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        #[derive(Deserialize)]
        struct Helper {
            #[serde(flatten)]
            key: Key,
            permissions: Vec<Permission>,
        }

        let Helper { key, permissions } = Helper::deserialize(deserializer)?;

        if !key.isSuperAdmin {
            if key.expiry == U40::ZERO {
                return Err(Error::custom("normal keys must have a non-zero expiry"));
            }

            if !permissions.iter().any(|perm| matches!(perm, Permission::Spend(_)))
                || !permissions.iter().any(|perm| matches!(perm, Permission::Call(_)))
            {
                return Err(Error::custom(
                    "normal keys must have at least one `spend` permission and one `call` permission",
                ));
            }
        }

        Ok(AuthorizeKey { key, permissions })
    }
}

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
    selector: FixedBytes<4>,
    /// The address of the contract this permission applies to.
    to: Address,
}

/// Represents spend permissions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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
    use alloy::primitives::{Address, Bytes, U256, fixed_bytes};

    use crate::types::{
        Call,
        Delegation::SpendPeriod,
        KeyType, U40,
        capabilities::{AuthorizeKey, CallPermission, Key, Permission, SpendPermission},
    };

    #[test]
    fn test_into_calls() {
        let key = AuthorizeKey {
            key: Key {
                expiry: U40::from(0),
                keyType: KeyType::P256,
                isSuperAdmin: true,
                publicKey: Bytes::from(fixed_bytes!(
                    "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
                )),
            },
            permissions: vec![
                Permission::Call(CallPermission {
                    to: Address::ZERO,
                    selector: fixed_bytes!("0xa9059cbb"),
                }),
                Permission::Spend(SpendPermission {
                    limit: U256::from(1000),
                    period: SpendPeriod::Day,
                    token: Address::ZERO,
                }),
            ],
        };

        let (authorize, calls) = key.clone().into_calls(Address::ZERO);

        assert_eq!(authorize, Call::authorize(Address::ZERO, key.clone().key));
        assert_eq!(calls.len(), 2);
        assert_eq!(
            calls[0],
            Call::set_can_execute(
                Address::ZERO,
                key.key.key_hash(),
                Address::ZERO,
                fixed_bytes!("0xa9059cbb"),
                true
            )
        );
        assert_eq!(
            calls[1],
            Call::set_spend_limit(
                Address::ZERO,
                key.key.key_hash(),
                Address::ZERO,
                SpendPeriod::Day,
                U256::from(1000)
            )
        );
    }

    #[test]
    fn serialize_authorize_key() {
        let key = AuthorizeKey {
            key: Key {
                expiry: U40::from(0),
                keyType: KeyType::P256,
                isSuperAdmin: true,
                publicKey: Bytes::from(fixed_bytes!(
                    "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
                )),
            },
            permissions: vec![
                Permission::Call(CallPermission {
                    to: Address::ZERO,
                    selector: fixed_bytes!("0xa9059cbb"),
                }),
                Permission::Spend(SpendPermission {
                    limit: U256::from(1000),
                    period: SpendPeriod::Day,
                    token: Address::ZERO,
                }),
            ],
        };

        assert_eq!(
            serde_json::to_string(&key).unwrap(),
            r#"{"expiry":"0x0","type":"p256","role":"admin","publicKey":"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef","permissions":[{"type":"call","selector":"0xa9059cbb","to":"0x0000000000000000000000000000000000000000"},{"type":"spend","limit":"0x3e8","period":"day","token":"0x0000000000000000000000000000000000000000"}]}"#
        );
    }

    #[test]
    fn deserialize_authorize_key() {
        let key = serde_json::from_str::<AuthorizeKey>(
            r#"{"expiry":"0x0","type":"p256","role":"admin","publicKey":"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef","permissions":[{"type":"call","selector":"0xa9059cbb","to":"0x0000000000000000000000000000000000000000"},{"type":"spend","limit":"0x3e8","period":"day","token":"0x0000000000000000000000000000000000000000"}]}"#
        ).unwrap();

        assert_eq!(
            key,
            AuthorizeKey {
                key: Key {
                    expiry: U40::from(0),
                    keyType: KeyType::P256,
                    isSuperAdmin: true,
                    publicKey: Bytes::from(fixed_bytes!(
                        "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
                    )),
                },
                permissions: vec![
                    Permission::Call(CallPermission {
                        to: Address::ZERO,
                        selector: fixed_bytes!("0xa9059cbb"),
                    }),
                    Permission::Spend(SpendPermission {
                        limit: U256::from(1000),
                        period: SpendPeriod::Day,
                        token: Address::ZERO,
                    }),
                ],
            }
        );
    }

    #[test]
    fn deserialize_authorize_key_no_permissions() {
        let err = serde_json::from_str::<AuthorizeKey>(
            r#"{"expiry":"0x1","type":"p256","role":"normal","publicKey":"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef","permissions":[]}"#
        ).unwrap_err();

        assert_eq!(
            err.to_string(),
            "normal keys must have at least one `spend` permission and one `call` permission"
        );
    }

    #[test]
    fn deserialize_authorize_key_insufficient_permissions() {
        let err = serde_json::from_str::<AuthorizeKey>(
            r#"{"expiry":"0x1","type":"p256","role":"normal","publicKey":"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef","permissions":[{"type":"call","selector":"0xa9059cbb","to":"0x0000000000000000000000000000000000000000"}]}"#
        ).unwrap_err();

        assert_eq!(
            err.to_string(),
            "normal keys must have at least one `spend` permission and one `call` permission"
        );

        let err = serde_json::from_str::<AuthorizeKey>(
            r#"{"expiry":"0x1","type":"p256","role":"normal","publicKey":"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef","permissions":[{"type":"spend","limit":"0x3e8","period":"day","token":"0x0000000000000000000000000000000000000000"}]}"#
        ).unwrap_err();

        assert_eq!(
            err.to_string(),
            "normal keys must have at least one `spend` permission and one `call` permission"
        );
    }

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
