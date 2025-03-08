//! RPC account-related request and response types.

use super::SendPreparedCallsResponse;
use crate::types::{
    SignedQuote,
    capabilities::{AuthorizeKey, AuthorizeKeyResponse},
};
use alloy::{
    eips::eip7702::SignedAuthorization,
    primitives::{Address, ChainId, PrimitiveSignature},
};
use serde::{Deserialize, Serialize};

/// Capabilities for `wallet_createAccount` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountCapabilities {
    /// Keys to authorize on the account.
    pub authorize_keys: Vec<AuthorizeKey>,
    /// Contract address to delegate to.
    pub delegation: Address,
}

/// Capabilities for `wallet_createAccount` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountResponseCapabilities {
    /// Keys that were authorized on the account.
    pub authorize_keys: Vec<AuthorizeKeyResponse>,
    /// Contract address the account was delegated to.
    pub delegation: Address,
}

/// Request parameters for `wallet_createAccount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountParameters {
    /// Capabilities.
    pub capabilities: CreateAccountCapabilities,
}

/// Response for `wallet_createAccount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountResponse {
    /// Address of the initialized account.
    pub address: Address,
    /// Capabilities.
    pub capabilities: CreateAccountResponseCapabilities,
}

/// Capabilities for `wallet_createAccount` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpgradeAccountCapabilities {
    /// Keys to authorize on the account.
    pub authorize_keys: Vec<AuthorizeKey>,
    /// Contract address to delegate to.
    pub delegation: Address,
    /// ERC20 token to pay for the gas of the calls.
    /// If `None`, the native token will be used.
    pub fee_token: Option<Address>,
}

/// Request parameters for `wallet_prepareUpgradeAccount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareUpgradeAccountParameters {
    /// Address of the EOA to upgrade.
    pub address: Address,
    /// Chain ID to initialize the account on.
    #[serde(with = "alloy::serde::quantity")]
    pub chain_id: ChainId,
    /// Capabilities.
    pub capabilities: UpgradeAccountCapabilities,
}

/// Request parameters for `wallet_upgradeAccount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeAccountParameters {
    /// The [`SignedQuote`] of the prepared call bundle.
    pub context: SignedQuote,
    /// Signature of the `wallet_prepareUpgradeAccount` digest.
    #[serde(with = "crate::serde::signature")]
    pub signature: PrimitiveSignature,
    /// Signed authorization.
    pub authorization: SignedAuthorization,
}

/// Response for `wallet_upgradeAccount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeAccountResponse {
    /// Call bundles that were executed.
    pub bundles: Vec<SendPreparedCallsResponse>,
}
