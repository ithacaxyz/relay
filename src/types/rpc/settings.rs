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
    /// Quote related configuration.
    pub quote_config: QuoteConfig,
}
