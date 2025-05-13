use crate::{config::QuoteConfig, types::FeeTokens};
use alloy::primitives::Address;
use serde::{Deserialize, Serialize};

/// The Relay capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayCapabilities {
    /// The contracts of the relay.
    pub contracts: RelayContracts,
    /// The fee configuration of the relay.
    pub fees: RelayFees,
}

/// Relay contracts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayContracts {
    /// The entrypoint address.
    pub entrypoint: Address,
    /// The delegation proxy address.
    pub delegation_proxy: Address,
    /// The delegation implementation address.
    ///
    /// This is directly fetched from the proxy.
    pub delegation_implementation: Address,
    /// The account registry address.
    pub account_registry: Address,
    /// The simulator address.
    pub simulator: Address,
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
