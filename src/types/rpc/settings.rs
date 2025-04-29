use crate::config::QuoteConfig;
use alloy::primitives::Address;
use serde::{Deserialize, Serialize};

/// The Relay settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelaySettings {
    /// Relay version.
    pub version: String,
    /// The entrypoint address.
    pub entrypoint: Address,
    /// The fee recipient address.
    pub fee_recipient: Address,
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
    /// Quote related configuration.
    pub quote_config: QuoteConfig,
}
