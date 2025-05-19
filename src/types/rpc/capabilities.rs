use crate::{
    config::QuoteConfig,
    types::{FeeTokens, VersionedContracts},
};
use alloy::primitives::Address;
use serde::{Deserialize, Serialize};

/// The Relay capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayCapabilities {
    /// The contracts of the relay.
    pub contracts: VersionedContracts,
    /// The fee configuration of the relay.
    pub fees: RelayFees,
}

/// Relay fee settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayFees {
    /// The fee recipient address.
    pub recipient: Address,
    /// Quote related configuration.
    pub quote_config: QuoteConfig,
    /// Tokens the fees can be paid in.
    pub tokens: FeeTokens,
}
