//! RPC account-related request and response types.

use super::{PrepareCallsContext, PrepareCallsResponse, SendPreparedCallsResponse};
use crate::types::capabilities::{AuthorizeKey, AuthorizeKeyResponse, RevokeKeyResponse};
use alloy::primitives::{Address, ChainId, PrimitiveSignature};
use serde::{Deserialize, Serialize};

/// Capabilities for `wallet_createAccount` request.
pub type CreateAccountCapabilities = AccountCapabilities<AuthorizeKey>;

/// Capabilities for `wallet_createAccount` response.
pub type CreateAccountResponseCapabilities = AccountCapabilities<AuthorizeKeyResponse>;

/// Capabilities for `wallet_createAccount` request and response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountCapabilities<T> {
    /// Authorize keys on the account.
    pub authorize_keys: Vec<T>,
    /// Contract address to delegate to.
    pub delegation: Address,
}

/// Request parameters for `wallet_createAccount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountParameters {
    /// Chain ID to initialize the account on.
    chain_id: ChainId,
    /// Request capabilities.
    capabilities: CreateAccountCapabilities,
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
    /// Capabilities.
    capabilities: CreateAccountCapabilities,
}

/// Response for `wallet_prepareUpgradeAccount`.
pub type PrepareUpgradeAccountResponse = PrepareCallsResponse;

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
