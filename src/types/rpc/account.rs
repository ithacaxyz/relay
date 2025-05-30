//! RPC account-related request and response types.

use super::{AuthorizeKey, AuthorizeKeyResponse, SendPreparedCallsResponse};
use crate::types::{KeyHash, KeyID, SignedCall};
use alloy::{
    dyn_abi::TypedData,
    primitives::{Address, B256, Bytes, ChainId, Signature},
    rpc::types::Authorization,
};
use serde::{Deserialize, Serialize};

/// Capabilities for `wallet_createAccount` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpgradeAccountCapabilities {
    /// Keys to authorize on the account.
    pub authorize_keys: Vec<AuthorizeKey>,
}

/// Request parameters for `wallet_prepareUpgradeAccount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareUpgradeAccountParameters {
    /// Address of the EOA to upgrade.
    pub address: Address,
    /// Chain ID to initialize the account on.
    #[serde(default, with = "alloy::serde::quantity::opt")]
    pub chain_id: Option<ChainId>,
    /// Capabilities.
    pub capabilities: UpgradeAccountCapabilities,
    /// Contract address to delegate to.
    pub delegation: Address,
}

/// Response for `wallet_prepareUpgradeAccount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareUpgradeAccountResponse {
    /// Chain ID to initialize the account on.
    #[serde(with = "alloy::serde::quantity")]
    pub chain_id: ChainId,
    /// Context that includes the prepared pre-call
    pub context: UpgradeAccountContext,
    /// Tuple of digests to be signed by the EOA root key. Includes the authorization digest and
    /// the pub pre-call digest.
    pub digests: UpgradeAccountDigests,
    /// EIP-712 typed data of the precall. This can be used to rebuild (and verify) the provided
    /// pub digest.
    pub typed_data: TypedData,
    /// Capabilities assigned to the account.
    pub capabilities: UpgradeAccountCapabilities,
}

/// Context for `wallet_upgradeAccount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpgradeAccountDigests {
    /// 7702 authorization digest.
    pub auth_digest: B256,
    /// Precall digest.
    pub pre_call_digest: B256,
}

/// Context for `wallet_upgradeAccount`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpgradeAccountContext {
    /// Address of the EOA to upgrade.
    pub address: Address,
    /// Chain ID to initialize the account on.
    #[serde(with = "alloy::serde::quantity")]
    pub chain_id: ChainId,
    /// Unsigned authorization object to be signed by the EOA root key.
    pub authorization: Authorization,
    /// Unsigned pre-call to be signed by the EOA root key.
    pub pre_call: SignedCall,
}

/// Request parameters for `wallet_upgradeAccount`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeAccountParameters {
    /// Context that includes the prepared pre-call as returned by `wallet_prepareUpgradeAccount`.
    pub context: UpgradeAccountContext,
    /// Signatures over the digests from `wallet_prepareUpgradeAccount`.
    pub signatures: UpgradeAccountSignatures,
}

/// Signatures over the digests from `wallet_prepareUpgradeAccount`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpgradeAccountSignatures {
    /// 7702 authorization digest.
    #[serde(with = "alloy::serde::displayfromstr")]
    pub auth: Signature,
    /// Precall digest.
    #[serde(with = "alloy::serde::displayfromstr")]
    pub pre_call: Signature,
}

/// Response for `wallet_upgradeAccount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeAccountResponse {
    /// Call bundles that were executed.
    pub bundles: Vec<SendPreparedCallsResponse>,
}

/// Request parameters for `wallet_getAccounts`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAccountsParameters {
    /// Key identifier.
    pub id: KeyID,
    /// Chain ID.
    pub chain_id: ChainId,
}

/// A response item from `wallet_getAccounts`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountResponse {
    /// Address of the account.
    pub address: Address,
    /// Delegation implementation address.
    pub delegation: Address,
    /// Authorized keys belonging to the account.
    pub keys: Vec<AuthorizeKeyResponse>,
}

/// Request parameters for `wallet_verifySignature`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifySignatureParameters {
    /// Account address.
    pub address: Address,
    /// Digest of the message to verify.
    pub digest: B256,
    /// The signature bytes
    pub signature: Bytes,
    /// Chain ID of the account with the given key configured.
    pub chain_id: ChainId,
}

/// Response from `wallet_verifySignature`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifySignatureResponse {
    /// Whether the signature is valid.
    pub valid: bool,
    /// Proof that can be used to verify the signature.
    pub proof: Option<ValidSignatureProof>,
}

/// Proof that can be used to verify output of `wallet_verifySignature`.
///
/// Signature is always verified against an account (either deployed or stored in relay storage).
/// [`ValidSignatureProof::account`] contains the address of account signature was verified against.
///
/// To verify that signature is valid for the returned account, user can call
/// `unwrapAndValidateSignature` on the returned account. For not yet delegated accounts, this call
/// will have to be preceeded by a
/// state override delegating the account to `DelegationAccount` contract and by executing
/// [`ValidSignatureProof::init_pre_call`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidSignatureProof {
    /// Address of an account (either delegated or stored) that the signature was verified against.
    pub account: Address,
    /// The key hash that signed the digest.
    pub key_hash: KeyHash,
    /// Initialization precall. Provided, if account is a stored account which has not
    /// been delegated.
    pub init_pre_call: Option<SignedCall>,
}
