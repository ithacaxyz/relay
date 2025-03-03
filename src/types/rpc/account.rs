//! RPC account-related request and response types.

use super::{PrepareCallsContext, PrepareCallsResponse, SendPreparedCallsResponse};
use crate::types::capabilities::{AuthorizeKey, AuthorizeKeyResponse, RevokeKeyResponse};
use alloy::primitives::{Address, ChainId, PrimitiveSignature};
use serde::{Deserialize, Serialize};

/// Capabilities for `wallet_createAccount` request and response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountCapabilities<T> {
    /// Authorize keys on the account.
    pub authorize_keys: Vec<T>,
    /// Contract address to delegate to.
    pub delegation: Address,
}

/// Capabilities for `wallet_createAccount` request.
pub type CreateAccountCapabilities = AccountCapabilities<AuthorizeKey>;

/// Capabilities for `wallet_createAccount` response.
pub type CreateAccountResponseCapabilities = AccountCapabilities<AuthorizeKeyResponse>;

/// Common `wallet_createAccount` parameters for request and responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountCommon<T> {
    /// Chain ID to initialize the account on.
    pub chain_id: ChainId,
    /// Capabilities.
    pub capabilities: T,
}

/// Request parameters for `wallet_createAccount`.
pub type CreateAccountParameters = CreateAccountCommon<CreateAccountCapabilities>;

/// Response for `wallet_createAccount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountResponse {
    /// Address of the initialized account.
    pub address: Address,
    /// `wallet_createAccount` response parameters.
    #[serde(flatten)]
    pub account: CreateAccountCommon<CreateAccountResponseCapabilities>,
}

/// Capabilities for `wallet_prepareCalls` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareCallsResponseCapabilities {
    /// Keys that were authorized on the account.
    pub authorize_keys: Option<Vec<AuthorizeKeyResponse>>,
    /// Keys that were revoked from the account.
    pub revoke_keys: Option<Vec<RevokeKeyResponse>>,
}

/// Request parameters for `wallet_prepareUpgradeAccount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareUpgradeAccountParameters {
    /// Address of the EOA to upgrade.
    pub address: Address,
    /// Chain ID to initialize the account on.
    pub chain_id: ChainId,
    /// Capabilities.
    pub capabilities: CreateAccountCapabilities,
}

/// Response for `wallet_prepareUpgradeAccount`.
pub type PrepareUpgradeAccountResponse = PrepareCallsResponse;

/// Request parameters for `wallet_upgradeAccount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeAccountParameters {
    /// Context of the prepared call bundle.
    pub context: PrepareCallsContext,
    /// Signature of the `wallet_prepareUpgradeAccount` digest.
    pub signature: PrimitiveSignature,
}

/// Response for `wallet_upgradeAccount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeAccountResponse {
    /// Call bundles that were executed.
    pub bundles: Vec<SendPreparedCallsResponse>,
}
