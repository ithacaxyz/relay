//! RPC calls-related request and response types.

use super::{AuthorizeKey, AuthorizeKeyResponse, KeySignature, Meta, RevokeKey};
use crate::types::{Call, SignedQuote, UserOp};
use alloy::{
    consensus::Eip658Value,
    primitives::{Address, B256, BlockHash, BlockNumber, ChainId, Log, TxHash, wrap_fixed_bytes},
};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

wrap_fixed_bytes! {
    /// An identifier for a call bundle.
    ///
    /// This is a unique identifier for a call bundle, which is used to track the status of the bundle.
    ///
    /// Clients should treat this as an opaque value and not attempt to parse it.
    pub struct BundleId<32>;
}

/// Request parameters for `wallet_prepareCalls`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareCallsParameters {
    /// Call bundle to prepare.
    pub calls: Vec<Call>,
    /// Target chain ID.
    #[serde(with = "alloy::serde::quantity")]
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
    #[serde(default)]
    pub authorize_keys: Vec<AuthorizeKey>,
    /// Extra request values.
    pub meta: Meta,
    /// Keys to revoke from the account.
    #[serde(default)]
    pub revoke_keys: Vec<RevokeKey>,
    /// Optional preOps to execute before signature verification.
    ///
    /// See [`UserOp::encodedPreOps`].
    #[serde(default)]
    pub pre_ops: Vec<UserOp>,
    /// Whether the call bundle is to be considered a preop.
    #[serde(default)]
    pub pre_op: bool,
}

/// Capabilities for `wallet_prepareCalls` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareCallsResponseCapabilities {
    /// Keys that were authorized on the account.
    #[serde(default)]
    pub authorize_keys: Vec<AuthorizeKeyResponse>,
    /// Keys that were revoked from the account.
    #[serde(default)]
    pub revoke_keys: Vec<RevokeKey>,
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
    /// UserOp key signature.
    pub signature: KeySignature,
}

/// Response for `wallet_sendPreparedCalls`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendPreparedCallsResponse {
    /// Transaction hash.
    /// TODO: use [`BundleId`] instead
    pub id: TxHash,
}

/// The status code of a call bundle.
#[derive(Debug, Clone, Serialize_repr, Deserialize_repr, Eq, PartialEq)]
#[repr(u16)]
pub enum CallStatusCode {
    /// The call bundle is pending.
    Pending = 100,
    /// The call bundle was confirmed.
    Confirmed = 200,
    /// The call bundle failed offchain.
    Failed = 300,
    /// The call bundle reverted fully onchain.
    Reverted = 400,
    /// The call bundle partially reverted onchain.
    PartiallyReverted = 500,
}

/// A receipt for a call bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallReceipt {
    /// The logs generated in the transaction.
    logs: Vec<Log>,
    /// The status of the transaction.
    status: Eip658Value,
    /// The block hash the transaction was included in.
    block_hash: BlockHash,
    /// The block number the transaction was included in.
    block_number: BlockNumber,
    /// The gas used by the transaction.
    gas_used: u64,
    /// The transaction hash.
    transaction_hash: TxHash,
}

/// The status of a call bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallsStatus {
    /// The ID of the call bundle.
    id: BundleId,
    /// The chain ID the bundle was broadcast on.
    // TODO: this should not be top-level, but instead be on the receipt object
    chain_id: ChainId,
    /// The status of the call bundle.
    status: CallStatusCode,
    receipts: Vec<CallReceipt>,
}
