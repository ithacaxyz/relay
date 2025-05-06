//! RPC calls-related request and response types.

use super::{AuthorizeKey, AuthorizeKeyResponse, Meta, RevokeKey};
use crate::{
    error::{RelayError, UserOpError},
    types::{AssetDiffs, Call, Key, KeyType, Op, PreOp, SignedQuote},
};
use alloy::{
    consensus::Eip658Value,
    dyn_abi::TypedData,
    primitives::{Address, B256, BlockHash, BlockNumber, Bytes, ChainId, TxHash, wrap_fixed_bytes},
    providers::DynProvider,
    rpc::types::Log,
    sol_types::SolEvent,
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

/// Key that will be used to sign the call bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallKey {
    /// Type of key.
    #[serde(rename = "type")]
    pub key_type: KeyType,
    /// Public key in encoded form.
    pub public_key: Bytes,
    /// Whether the digest will be prehashed by the key.
    pub prehash: bool,
}

impl CallKey {
    /// The key hash.
    ///
    /// The hash is computed as `keccak256(abi.encode(key.keyType, keccak256(key.publicKey)))`.
    pub fn key_hash(&self) -> B256 {
        Key::hash(self.key_type, &self.public_key)
    }
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
    /// Address of the account to prepare the call bundle for. It can only be None, if we are
    /// handling a preop
    pub from: Option<Address>,
    /// Request capabilities.
    pub capabilities: PrepareCallsCapabilities,
    /// Key that will be used to sign the call bundle.
    pub key: CallKey,
}

impl PrepareCallsParameters {
    /// Ensures there are only whitelisted calls in preops.
    pub fn check_preop_calls(&self) -> Result<(), RelayError> {
        let has_unallowed = |calls: &[Call]| {
            calls.iter().any(|call| !call.is_whitelisted_preop(self.from.unwrap_or_default()))
        };

        if self.capabilities.pre_op && has_unallowed(&self.calls) {
            return Err(UserOpError::UnallowedPreOpCalls.into());
        }

        for op in &self.capabilities.pre_ops {
            if has_unallowed(&op.calls().map_err(RelayError::from)?) {
                return Err(UserOpError::UnallowedPreOpCalls.into());
            }
        }

        Ok(())
    }
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
    pub pre_ops: Vec<PreOp>,
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
    /// The [`AssetDiff`] of the prepared call bundle.
    pub asset_diff: AssetDiffs,
}

/// Response for `wallet_prepareCalls`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareCallsResponse {
    /// The [`PrepareCallsContext`] of the prepared call bundle.
    pub context: PrepareCallsContext,
    /// Digest of the prepared call bundle for the user to sign over
    /// with an authorized key.
    pub digest: B256,
    /// EIP-712 payload corresponding to the digest.
    pub typed_data: TypedData,
    /// Capabilities response.
    pub capabilities: PrepareCallsResponseCapabilities,
    /// Key that will be used to sign the call bundle.
    #[serde(default)]
    pub key: Option<CallKey>,
}

/// Response context from `wallet_prepareCalls`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PrepareCallsContext {
    /// The [`SignedQuote`] of the prepared call bundle.
    #[serde(rename = "quote")]
    Quote(Box<SignedQuote>),
    /// The [`PreOp`] of the prepared call bundle.
    #[serde(rename = "preOp")]
    PreOp(PreOp),
}

impl PrepareCallsContext {
    /// Initializes [`PrepareCallsContext`] with a [`SignedQuote`].
    pub fn with_quote(quote: SignedQuote) -> Self {
        Self::Quote(Box::new(quote))
    }

    /// Initializes [`PrepareCallsContext`] with a [`PreOp`].
    pub fn with_preop(preop: PreOp) -> Self {
        Self::PreOp(preop)
    }

    /// Returns quote mutable reference if it exists.
    pub fn quote(&self) -> Option<&SignedQuote> {
        match self {
            PrepareCallsContext::Quote(signed) => Some(signed),
            PrepareCallsContext::PreOp(_) => None,
        }
    }

    /// Returns quote mutable reference if it exists.
    pub fn quote_mut(&mut self) -> Option<&mut SignedQuote> {
        match self {
            PrepareCallsContext::Quote(signed) => Some(signed),
            PrepareCallsContext::PreOp(_) => None,
        }
    }

    /// Consumes self and returns quote if it exists.
    pub fn take_quote(self) -> Option<SignedQuote> {
        match self {
            PrepareCallsContext::Quote(signed) => Some(*signed),
            PrepareCallsContext::PreOp(_) => None,
        }
    }

    /// Consumes self and returns preop if it exists.
    pub fn take_preop(self) -> Option<PreOp> {
        match self {
            PrepareCallsContext::Quote(_) => None,
            PrepareCallsContext::PreOp(preop) => Some(preop),
        }
    }

    /// Calculate the eip712 digest that the user will need to sign.
    pub async fn compute_eip712_data(
        &self,
        entrypoint_address: Address,
        provider: &DynProvider,
    ) -> eyre::Result<(B256, TypedData)> {
        match self {
            PrepareCallsContext::Quote(quote) => {
                quote.ty().op.compute_eip712_data(entrypoint_address, provider).await
            }
            PrepareCallsContext::PreOp(pre_op) => {
                pre_op.compute_eip712_data(entrypoint_address, provider).await
            }
        }
    }
}

/// Capabilities for `wallet_sendPreparedCalls` request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendPreparedCallsCapabilities {
    /// Fee payment signature.
    pub fee_signature: Bytes,
}

/// Request parameters for `wallet_sendPreparedCalls`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendPreparedCallsParameters {
    /// The [`SendPreparedCallsCapabilities`] of the prepared call bundle.
    #[serde(default)]
    pub capabilities: SendPreparedCallsCapabilities,
    /// The [`PrepareCallsContext`] of the prepared call bundle.
    pub context: PrepareCallsContext,
    /// Key that was used to sign the call bundle.
    pub key: CallKey,
    /// Signature value.
    pub signature: Bytes,
}

/// Response for `wallet_sendPreparedCalls`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendPreparedCallsResponse {
    /// Bundle ID.
    pub id: BundleId,
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

impl CallStatusCode {
    /// Whether the bundle is pending.
    pub fn is_pending(&self) -> bool {
        matches!(self, CallStatusCode::Pending)
    }

    /// Whether the bundle status is final.
    pub fn is_final(&self) -> bool {
        !self.is_pending()
    }

    /// Whether the bundle was confirmed.
    pub fn is_confirmed(&self) -> bool {
        matches!(self, CallStatusCode::Confirmed)
    }
}

/// A receipt for a call bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallReceipt {
    /// The chain ID the transaction was included in.
    pub chain_id: ChainId,
    /// The logs generated in the transaction.
    pub logs: Vec<Log>,
    /// The status of the transaction.
    #[serde(flatten)]
    pub status: Eip658Value,
    /// The block hash the transaction was included in.
    pub block_hash: Option<BlockHash>,
    /// The block number the transaction was included in.
    pub block_number: Option<BlockNumber>,
    /// The gas used by the transaction.
    pub gas_used: u64,
    /// The transaction hash.
    pub transaction_hash: TxHash,
}

impl CallReceipt {
    /// Attempts to decode the logs to the provided log type.
    ///
    /// Returns the first log that decodes successfully.
    ///
    /// Returns None, if none of the logs could be decoded to the provided log type or if there
    /// are no logs.
    pub fn decoded_log<E: SolEvent>(&self) -> Option<alloy::primitives::Log<E>> {
        self.logs.iter().find_map(|log| E::decode_log(&log.inner).ok())
    }
}

/// The status of a call bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallsStatus {
    /// The ID of the call bundle.
    pub id: BundleId,
    /// The status of the call bundle.
    pub status: CallStatusCode,
    /// The receipts for the call bundle.
    pub receipts: Vec<CallReceipt>,
}
