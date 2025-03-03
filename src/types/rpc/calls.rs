//! RPC calls-related request and response types.

use super::PrepareCallsResponseCapabilities;
use crate::types::{
    Call, KeyType, PartialUserOp, SignedQuote,
    capabilities::{AuthorizeKey, Meta, RevokeKey},
};
use alloy::primitives::{Address, B256, Bytes, ChainId, PrimitiveSignature};
use serde::{Deserialize, Serialize};

/// Request parameters for `wallet_prepareCalls`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareCallsParameters {
    /// Call bundle to prepare.
    calls: Vec<Call>,
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
