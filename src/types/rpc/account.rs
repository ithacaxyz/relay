//! RPC account-related request and response types.

use super::{PrepareCallsContext, PrepareCallsResponse, SendPreparedCallsResponse};
use crate::types::capabilities::{AuthorizeKey, AuthorizeKeyResponse};
use alloy::primitives::{Address, ChainId, PrimitiveSignature};
use serde::{Deserialize, Serialize};

/// Generic capabilities for account creation shared between request and response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountCapabilities<T> {
    /// Authorized keys on the account.
    pub authorize_keys: Vec<T>,
    /// Contract address to delegate to.
    pub delegation: Address,
}

/// Capabilities for `wallet_createAccount` request.
pub type CreateAccountCapabilities = AccountCapabilities<AuthorizeKey>;
/// Capabilities for `wallet_createAccount` response.
pub type CreateAccountResponseCapabilities = AccountCapabilities<AuthorizeKeyResponse>;

/// Common parameters for `wallet_createAccount` shared between request and response.
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
