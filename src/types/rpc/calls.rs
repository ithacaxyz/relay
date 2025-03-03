//! RPC calls-related request and response types.

use crate::types::{
    Call, KeyType, PartialUserOp, SignedQuote,
    capabilities::{AuthorizeKey, AuthorizeKeyResponse, Meta, RevokeKey},
};
use alloy::primitives::{Address, B256, Bytes, ChainId, PrimitiveSignature};
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

/// Generic helper for key capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyCapabilities<A> {
    /// Keys to authorize on the account.
    pub authorize_keys: Option<Vec<A>>,
    /// Keys to revoke from the account.
    pub revoke_keys: Option<Vec<RevokeKey>>,
}

/// Capabilities for `wallet_prepareCalls` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareCallsCapabilities {
    /// Extra request values.
    pub meta: Meta,
    /// Key capabilities.
    #[serde(flatten)]
    pub key_capabilities: KeyCapabilities<AuthorizeKey>,
}

/// Capabilities for `wallet_prepareCalls` response.
pub type PrepareCallsResponseCapabilities = KeyCapabilities<AuthorizeKeyResponse>;

/// Response for `wallet_prepareCalls`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareCallsResponse {
    /// Chain ID the calls were prepared for.
    pub chain_id: ChainId,
    /// Context.
    pub context: PrepareCallsContext,
    /// Digest of the prepared call bundle for the user to sign over
    /// with an authorized key.
    pub digest: B256,
    /// Capabilities response.
    pub capabilities: PrepareCallsResponseCapabilities,
}

/// Context for `wallet_prepareCalls`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrepareCallsContext {
    /// Signed [`Quote`].
    pub quote: SignedQuote,
    /// Partial [`UserOp`].
    pub op: PartialUserOp,
}

/// Request parameters for `wallet_sendPreparedCalls`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendPreparedCallsParameters {
    /// Chain ID the calls are being submitted to.
    pub chain_id: ChainId,
    /// Context of the prepared call bundle.
    pub context: PrepareCallsContext,
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
    pub value: PrimitiveSignature,
}

/// Response for `wallet_sendPreparedCalls`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendPreparedCallsResponse {
    /// Bundle identifier.
    pub id: String,
}
