//! RPC key-related request and response types.

use alloy::primitives::{Address, B256, Bytes, ChainId};
use serde::{Deserialize, Serialize};

use crate::{
    error::KeysError,
    types::{Call, Key, KeyHash, KeyType},
};

use super::Permission;
use std::collections::HashMap;

/// Request parameters for `wallet_getKeys`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetKeysParameters {
    /// Address of the account to get the keys for.
    pub address: Address,
    /// Target chain IDs. If not provided, returns keys for all supported chains.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[serde(with = "alloy::serde::quantity::vec")]
    pub chain_ids: Vec<ChainId>,
}

/// Response for wallet_getKeys with multi-chain support.
/// Maps chain ID (as hex string) to array of authorized keys for that chain.
/// Chains where the account is not delegated or where errors occurred are omitted.
pub type GetKeysResponse = HashMap<String, Vec<AuthorizeKeyResponse>>;

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
    /// [`Intent`] if the key does not already exist.
    ///
    /// The second set of calls is to add call permissions and spending limits to the key.
    ///
    /// The third set of calls is to register the mapping from key id to account address in a
    /// registry.
    pub fn into_calls(mut self) -> Result<(Call, Vec<Call>), KeysError> {
        let mut calls = Vec::new();

        if self.key.isSuperAdmin && self.key_type().is_p256() {
            return Err(KeysError::P256SessionKeyOnly);
        }

        calls.extend(self.permissions.drain(..).map(|perm| match perm {
            Permission::Call(perm) => {
                Call::set_can_execute(self.key.key_hash(), perm.to, perm.selector, true)
            }
            Permission::Spend(perm) => {
                Call::set_spend_limit(self.key.key_hash(), perm.token, perm.period, perm.limit)
            }
        }));

        Ok((Call::authorize(self.key), calls))
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
    pub hash: B256,
    /// The key to authorize or modify permissions for.
    #[serde(flatten)]
    pub authorize_key: AuthorizeKey,
}

/// Represents a key revocation request.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeKey {
    /// Key hash to revoke.
    pub hash: B256,
}

impl RevokeKey {
    /// Transform into a series of calls.
    pub fn into_calls(self) -> Vec<Call> {
        vec![Call::revoke(self.hash)]
    }
}

/// Key Signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeySignature {
    /// Public key that generated the signature.
    pub public_key: Bytes,
    /// Type of key that generated the signature.
    #[serde(rename = "type")]
    pub key_type: KeyType,
    /// Signature value.
    pub value: Bytes,
    /// Whether it should prehash before verifying the signature.
    #[serde(default)]
    pub prehash: bool,
}

impl KeySignature {
    /// Returns the associated [`KeyHash`].
    pub fn key_hash(&self) -> KeyHash {
        Key::hash(self.key_type, &self.public_key)
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{Address, B256, Bytes, U256, fixed_bytes};

    use crate::types::{
        Call, CallPermission,
        IthacaAccount::SpendPeriod,
        Key, KeyType, U40,
        rpc::{AuthorizeKey, AuthorizeKeyResponse, Permission, RevokeKey, SpendPermission},
    };

    #[test]
    fn test_authorize_into_calls() {
        let key = AuthorizeKey {
            key: Key {
                expiry: U40::from(0),
                keyType: KeyType::P256,
                isSuperAdmin: false,
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

        let (authorize, calls) = key.clone().into_calls().unwrap();

        assert_eq!(authorize, Call::authorize(key.clone().key));
        assert_eq!(calls.len(), 2);
        assert_eq!(
            calls[0],
            Call::set_can_execute(
                key.key.key_hash(),
                Address::ZERO,
                fixed_bytes!("0xa9059cbb"),
                true
            )
        );
        assert_eq!(
            calls[1],
            Call::set_spend_limit(
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
                isSuperAdmin: false,
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
            r#"{"expiry":"0x0","type":"p256","role":"normal","publicKey":"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef","permissions":[{"type":"call","selector":"0xa9059cbb","to":"0x0000000000000000000000000000000000000000"},{"type":"spend","limit":"0x3e8","period":"day","token":"0x0000000000000000000000000000000000000000"}]}"#
        );
    }

    #[test]
    fn serialize_authorize_key_response() {
        let key = Key {
            expiry: U40::from(0),
            keyType: KeyType::P256,
            isSuperAdmin: false,
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
            r#"{"hash":"0xc7982d8475577e50ca7dc56923eb413813cdb93f009160d943436b217410ffd9","expiry":"0x0","type":"p256","role":"normal","publicKey":"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef","permissions":[{"type":"call","selector":"0xa9059cbb","to":"0x0000000000000000000000000000000000000000"}]}"#
        );
    }

    #[test]
    fn deserialize_authorize_key_response() {
        let resp = serde_json::from_str::<AuthorizeKeyResponse>(
            r#"{"hash":"0xc7982d8475577e50ca7dc56923eb413813cdb93f009160d943436b217410ffd9","expiry":"0x0","type":"p256","role":"normal","publicKey":"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef","permissions":[{"type":"call","selector":"0xa9059cbb","to":"0x0000000000000000000000000000000000000000"}]}"#
        ).unwrap();

        let key = Key {
            expiry: U40::from(0),
            keyType: KeyType::P256,
            isSuperAdmin: false,
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
                    })],
                },
            }
        );
    }

    #[test]
    fn test_revoke_key_into_calls() {
        let hash = B256::random();

        let revoke = RevokeKey { hash };
        assert_eq!(revoke.into_calls(), vec![Call::revoke(hash)]);
    }

    #[test]
    fn test_get_keys_parameters_roundtrip() {
        // Test with chain_ids specified
        let raw =
            r#"{"address":"0x0000000000000000000000000000000000000000","chainIds":["0x1","0xa"]}"#;
        let params =
            super::GetKeysParameters { address: Address::ZERO, chain_ids: vec![1u64, 10u64] };

        let json = serde_json::to_string(&params).unwrap();
        assert_eq!(json, raw);
        let deserialized: super::GetKeysParameters = serde_json::from_str(&json).unwrap();

        assert_eq!(params.address, deserialized.address);
        assert_eq!(params.chain_ids, deserialized.chain_ids);

        // Test with empty chain_ids (should omit field in JSON)
        let params_no_chains =
            super::GetKeysParameters { address: Address::ZERO, chain_ids: vec![] };

        let json_no_chains = serde_json::to_string(&params_no_chains).unwrap();
        assert_eq!(json_no_chains, r#"{"address":"0x0000000000000000000000000000000000000000"}"#);

        // Test deserialization with missing chain_ids (should default to empty vec)
        let deserialized_no_chains: super::GetKeysParameters =
            serde_json::from_str(r#"{"address":"0x0000000000000000000000000000000000000000"}"#)
                .unwrap();
        assert_eq!(deserialized_no_chains.chain_ids.len(), 0);
    }
}
