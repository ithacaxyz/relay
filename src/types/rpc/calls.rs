//! RPC calls-related request and response types.

use crate::types::{
    Call, KeyType, SignedQuote,
    capabilities::{AuthorizeKey, AuthorizeKeyResponse, Meta, RevokeKey},
};
use alloy::primitives::{Address, B256, Bytes, ChainId};
use serde::{Deserialize, Serialize};

/// Request parameters for `wallet_prepareCalls`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareCallsParameters {
    /// Call bundle to prepare.
    pub calls: Vec<Call>,
    /// Target chain ID.
    pub chain_id: ChainId,
    /// Address of the account to prepare the call bundle for.
    pub from: Address,
    /// Request capabilities.
    pub capabilities: PrepareCallsCapabilities,
}

/// Capabilities for `wallet_prepareCalls` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareCallsCapabilities {
    /// Keys to authorize on the account.
    pub authorize_keys: Option<Vec<AuthorizeKey>>,
    /// Extra request values.
    pub meta: Meta,
    /// Keys to revoke from the account.
    pub revoke_keys: Option<Vec<RevokeKey>>,
}

/// Capabilities for `wallet_prepareCalls` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareCallsResponseCapabilities {
    /// Keys that were authorized on the account.
    pub authorize_keys: Option<Vec<AuthorizeKeyResponse>>,
    /// Keys that were revoked from the account.
    pub revoke_keys: Option<Vec<RevokeKey>>,
}

/// Response for `wallet_prepareCalls`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareCallsResponse {
    /// The [`SignedQuote`] of the prepared call bundle.
    pub context: SignedQuote,
    /// Digest of the prepared call bundle for the user to sign over
    /// with an authorized key.
    pub digest: B256,
    /// Capabilities response.
    pub capabilities: PrepareCallsResponseCapabilities,
}

/// Request parameters for `wallet_sendPreparedCalls`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendPreparedCallsParameters {
    /// The [`SignedQuote`] of the prepared call bundle.
    pub context: SignedQuote,
    /// Signature values.
    pub signature: SendPreparedCallsSignature,
}

/// Signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendPreparedCallsSignature {
    /// Public key that generated the signature.
    pub public_key: Bytes,
    /// Type of key that generated the signature.
    #[serde(rename = "type")]
    pub key_type: KeyType,
    /// Signature value.
    pub value: Bytes,
}

/// Response for `wallet_sendPreparedCalls`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendPreparedCallsResponse {
    /// Bundle identifier.
    pub id: String,
}
