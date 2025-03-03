use alloy::primitives::{Address, B256, Bytes, ChainId, PrimitiveSignature, U256};
use serde::{Deserialize, Serialize};

use super::{
    Key, KeyType, PartialUserOp, SignedQuote,
    capabilities::{AuthorizeKey, AuthorizeKeyResponse, Meta, RevokeKey, RevokeKeyResponse},
};

/// Request parameters for `wallet_createAccount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountParameters {
    /// Chain ID to initialize the account on.
    chain_id: ChainId,
    /// Request capabilities.
    capabilities: CreateAccountCapabilities,
}

/// Capabilities for `wallet_createAccount` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountCapabilities {
    /// Keys to authorize on the account.
    authorize_keys: Vec<AuthorizeKey>,
    /// Contract address to delegate to.
    delegation: Address,
}

/// Response for `wallet_createAccount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountResponse {
    /// Address of the initialized account.
    address: Address,
    /// Chain ID the account was initialized on.
    chain_id: ChainId,
    /// Capabilities.
    capabilities: CreateAccountResponseCapabilities,
}

/// Capabilities for `wallet_createAccount` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountResponseCapabilities {
    /// Keys that were authorized on the account.
    authorize_keys: Vec<AuthorizeKeyResponse>,
    /// Contract address the account was delegated to.
    delegation: Address,
}

/// Request parameters for `wallet_getKeys`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetKeysParameters {
    /// Address of the account to get the keys for.
    address: Address,
}

/// Account key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetKeyResponse {
    /// Key hash.
    hash: B256,
    /// Key.
    #[serde(flatten)]
    key: Key,
}

/// Response for `wallet_getKeys`.
pub type GetKeysResponse = Vec<GetKeyResponse>;

/// Request parameters for `wallet_prepareCalls`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareCallsParameters {
    /// Call bundle to prepare.
    calls: Vec<RpcCall>,
    /// Target chain ID.
    chain_id: ChainId,
    /// Address of the account to prepare the call bundle for.
    from: Address,
    /// Request capabilities.
    capabilities: PrepareCallsCapabilities,
}

/// Capabilities for `wallet_prepareCalls` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareCallsCapabilities {
    /// Keys to authorize on the account.
    authorize_keys: Option<Vec<AuthorizeKey>>,
    /// Extra request values.
    meta: Meta,
    /// Keys to revoke from the account.
    revoke_keys: Option<Vec<RevokeKey>>,
}

/// Response for `wallet_prepareCalls`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareCallsResponse {
    /// Chain ID the calls were prepared for.
    chain_id: ChainId,
    /// Context.
    context: PrepareCallsContext,
    /// Digest of the prepared call bundle for the user to sign over
    /// with an authorized key.
    digest: B256,
    /// Capabilities response.
    capabilities: PrepareCallsResponseCapabilities,
}

/// Context for `wallet_prepareCalls`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrepareCallsContext {
    /// Signed [`Quote`].
    quote: SignedQuote,
    /// Partial [`UserOp`].
    op: PartialUserOp,
}

/// Capabilities for `wallet_prepareCalls` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareCallsResponseCapabilities {
    /// Keys that were authorized on the account.
    authorize_keys: Option<Vec<AuthorizeKeyResponse>>,
    /// Keys that were revoked from the account.
    revoke_keys: Option<Vec<RevokeKeyResponse>>,
}

/// Request parameters for `wallet_prepareUpgradeAccount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareUpgradeAccountParameters {
    /// Address of the EOA to upgrade.
    address: Address,
    /// Chain ID to initialize the account on.
    chain_id: ChainId,
    /// Contract address to delegate to.
    delegation: Address,
    /// Capabilities.
    capabilities: CreateAccountCapabilities,
}

/// Response for `wallet_prepareUpgradeAccount`.
pub type PrepareUpgradeAccountResponse = PrepareCallsResponse;

/// RPC call parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcCall {
    /// Calldata.
    data: Option<Bytes>,
    /// Target address.
    to: Address,
    /// Value (in wei) to transfer.
    value: Option<U256>,
}

/// Request parameters for `wallet_sendPreparedCalls`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendPreparedCallsParameters {
    /// Chain ID the calls are being submitted to.
    chain_id: ChainId,
    /// Context of the prepared call bundle.
    context: PrepareCallsContext,
    /// Signature values.
    signature: SendPreparedCallsSignature,
}

/// Signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendPreparedCallsSignature {
    /// Public key that generated the signature.
    public_key: Bytes,
    /// Type of key that generated the signature.
    #[serde(rename = "type")]
    key_type: KeyType,
    /// Signature value.
    value: PrimitiveSignature,
}

/// Response for `wallet_sendPreparedCalls`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendPreparedCallsResponse {
    /// Bundle identifier.
    id: String,
}

/// Request parameters for `wallet_upgradeAccount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeAccountParameters {
    /// Context of the prepared call bundle.
    context: PrepareCallsContext,
    /// Signature of the `wallet_prepareUpgradeAccount` digest.
    signature: PrimitiveSignature,
}

/// Response for `wallet_upgradeAccount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeAccountResponse {
    /// Call bundles that were executed.
    bundles: Vec<SendPreparedCallsResponse>,
}

mod tests {
    use alloy::primitives::{Bytes, PrimitiveSignature};
    use std::str::FromStr;

    use crate::types::{KeyType, SendPreparedCallsSignature};

    #[test]
    fn test_deserialize_send_prepared_calls_signature() {
        let serialized = r#"{"publicKey":"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef","type":"p256","value":{"r":"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef","s":"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef","yParity":"0x0","v":"0x0"}}"#;
        let signature = serde_json::from_str::<SendPreparedCallsSignature>(serialized).unwrap();
        assert_eq!(
            signature.public_key,
            Bytes::from_str("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
                .unwrap()
        );
        assert_eq!(signature.key_type, KeyType::P256);
        assert_eq!(signature.value, PrimitiveSignature::from_str("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef00").unwrap());
    }
}
