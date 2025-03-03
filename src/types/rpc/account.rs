//! RPC account-related request and response types.

use super::{PrepareCallsContext, SendPreparedCallsResponse};
use crate::types::capabilities::{AuthorizeKey, AuthorizeKeyResponse};
use alloy::primitives::{Address, ChainId, PrimitiveSignature};
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
    /// Chain ID to initialize the account on.
    pub chain_id: ChainId,
    /// Capabilities.
    pub capabilities: CreateAccountCapabilities,
}

/// Response for `wallet_createAccount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountResponse {
    /// Address of the initialized account.
    pub address: Address,
    /// Chain ID to initialize the account on.
    pub chain_id: ChainId,
    /// Capabilities.
    pub capabilities: CreateAccountResponseCapabilities,
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
