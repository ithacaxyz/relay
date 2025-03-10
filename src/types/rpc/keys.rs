//! RPC key-related request and response types.

use alloy::primitives::{Address, B256};
use serde::{Deserialize, Serialize};

use crate::types::{Call, Key, KeyType};

use super::Permission;

/// Request parameters for `wallet_getKeys`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetKeysParameters {
    /// Address of the account to get the keys for.
    pub address: Address,
}

/// Represents a key authorization request.
///
/// If the key does not exist, it is added to the account, along with the permissions.
///
/// If the key already exists, the permissions are updated.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizeKey {
    /// The key to authorize or modify permissions for.
    #[serde(flatten)]
    pub key: Key,
    /// The permissions for the key.
    pub permissions: Vec<Permission>,
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

    /// Returns the inner [`KeyType`].
    pub fn key_type(&self) -> KeyType {
        self.key.keyType
    }

    /// Convert `self` into [`AuthorizeKeyResponse`].
    pub fn into_response(self) -> AuthorizeKeyResponse {
        AuthorizeKeyResponse { hash: self.key.key_hash(), authorize_key: self }
    }
}

/// Represents a key authorization response.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct AuthorizeKeyResponse {
    /// Key hash.
    hash: B256,
    /// The key to authorize or modify permissions for.
    #[serde(flatten)]
    authorize_key: AuthorizeKey,
}

/// Represents a key revocation request.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeKey {
    /// Key hash to revoke.
    hash: B256,
}

impl RevokeKey {
    /// Transform into a call.
    pub fn into_call(self, eoa: Address) -> Call {
        Call::revoke(eoa, self.hash)
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{Address, B256, Bytes, U256, fixed_bytes};

    use crate::types::{
        Call,
        Delegation::SpendPeriod,
        Key, KeyType, U40,
        rpc::{
            AuthorizeKey, AuthorizeKeyResponse, CallPermission, Permission, RevokeKey,
            SpendPermission,
        },
    };

    #[test]
    fn test_authorize_into_calls() {
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
    fn serialize_authorize_key_response() {
        let key = Key {
            expiry: U40::from(0),
            keyType: KeyType::P256,
            isSuperAdmin: true,
            publicKey: Bytes::from(fixed_bytes!(
                "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
            )),
        };
        let resp = AuthorizeKeyResponse {
            hash: key.key_hash(),
            authorize_key: AuthorizeKey {
                key,
                permissions: vec![Permission::Call(CallPermission {
                    to: Address::ZERO,
                    selector: fixed_bytes!("0xa9059cbb"),
                })],
            },
        };

        assert_eq!(
            serde_json::to_string(&resp).unwrap(),
            r#"{"hash":"0xc7982d8475577e50ca7dc56923eb413813cdb93f009160d943436b217410ffd9","expiry":"0x0","type":"p256","role":"admin","publicKey":"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef","permissions":[{"type":"call","selector":"0xa9059cbb","to":"0x0000000000000000000000000000000000000000"}]}"#
        );
    }

    #[test]
    fn deserialize_authorize_key_response() {
        let resp = serde_json::from_str::<AuthorizeKeyResponse>(
            r#"{"hash":"0xc7982d8475577e50ca7dc56923eb413813cdb93f009160d943436b217410ffd9","expiry":"0x0","type":"p256","role":"admin","publicKey":"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef","permissions":[{"type":"call","selector":"0xa9059cbb","to":"0x0000000000000000000000000000000000000000"}]}"#
        ).unwrap();

        let key = Key {
            expiry: U40::from(0),
            keyType: KeyType::P256,
            isSuperAdmin: true,
            publicKey: Bytes::from(fixed_bytes!(
                "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
            )),
        };

        assert_eq!(
            resp,
            AuthorizeKeyResponse {
                hash: key.key_hash(),
                authorize_key: AuthorizeKey {
                    key,
                    permissions: vec![Permission::Call(CallPermission {
                        to: Address::ZERO,
                        selector: fixed_bytes!("0xa9059cbb"),
                    })]
                },
            }
        );
    }

    #[test]
    fn test_revoke_key_into_call() {
        let address = Address::random();
        let hash = B256::random();

        let revoke = RevokeKey { hash };

        assert_eq!(revoke.into_call(address), Call::revoke(address, hash));
    }
}
