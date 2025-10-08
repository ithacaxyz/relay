//! RPC account-related request and response types.

use super::{AuthorizeKey, AuthorizeKeyResponse, SendPreparedCallsResponse};
use crate::types::{KeyHash, KeyID, SignedCall};
use alloy::{
    dyn_abi::TypedData,
    eips::eip7702::SignedAuthorization,
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
    pub auth: B256,
    /// Precall execution digest.
    pub exec: B256,
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
    /// 7702 authorization signature.
    #[serde(with = "alloy::serde::displayfromstr")]
    pub auth: Signature,
    /// Precall execution signature.
    #[serde(with = "alloy::serde::displayfromstr")]
    pub exec: Signature,
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
    #[serde(with = "alloy::serde::quantity")]
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
    #[serde(with = "alloy::serde::quantity")]
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

/// Parameters for `account_setEmail`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetEmailParameters {
    /// The email to associate with the wallet.
    pub email: String,
    /// The wallet address.
    pub wallet_address: Address,
}

/// Parameters for `account_verifyEmail`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyEmailParameters {
    /// Chain ID that the account is on.
    #[serde(with = "alloy::serde::quantity")]
    pub chain_id: ChainId,
    /// The email to associate with the wallet.
    pub email: String,
    /// The wallet address.
    pub wallet_address: Address,
    /// The verification token.
    pub token: String,
    /// The signature over `keccak(email ++ token)` from the account the e-mail should be
    /// associated with.
    pub signature: Bytes,
}

/// Request parameters for `wallet_getAuthorization`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAuthorizationParameters {
    /// Address of the account to get authorization for.
    pub address: Address,
}

/// Response for `wallet_getAuthorization`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAuthorizationResponse {
    /// The signed authorization for account delegation.
    pub authorization: SignedAuthorization,
    /// The initialization data.
    pub data: Bytes,
    /// The address of the initializer.
    pub to: Address,
}

/// Parameters for `account_setPhone`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetPhoneParameters {
    /// The phone number to associate with the wallet.
    pub phone: String,
    /// The wallet address.
    pub wallet_address: Address,
}

/// Parameters for `account_verifyPhone`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyPhoneParameters {
    /// The phone number to verify.
    pub phone: String,
    /// The verification code.
    pub code: String,
    /// The wallet address.
    pub wallet_address: Address,
}

/// Parameters for `account_resendVerifyPhone`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResendVerifyPhoneParameters {
    /// The phone number to resend verification to.
    pub phone: String,
    /// The wallet address.
    pub wallet_address: Address,
}

/// Parameters for `account_onrampStatus`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OnrampStatusParameters {
    /// The wallet address to check.
    pub address: Address,
}

/// Response for `account_onrampStatus`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OnrampStatusResponse {
    /// Unix timestamp (seconds) when email was verified, or null if not verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<u64>,
    /// Unix timestamp (seconds) when phone was verified, or null if not verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone: Option<u64>,
}

/// Request parameters for `account_getOnrampContactInfo`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetOnrampContactInfoParameters {
    /// The wallet address to get contact info for.
    pub address: Address,
    /// Secret for authentication.
    pub secret: String,
}

/// Response for `account_getOnrampContactInfo`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetOnrampContactInfoResponse {
    /// Verified email address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Verified phone number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    /// Unix timestamp (seconds) when phone was verified, or null if not verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone_verified_at: Option<u64>,
}
