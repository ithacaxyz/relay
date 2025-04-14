use crate::config::{EntryWithDelegation, QuoteConfig};
use alloy::primitives::Address;
use serde::{Deserialize, Serialize};

/// The Relay settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelaySettings {
    /// Relay version.
    pub version: String,
    /// The entrypoint and delegation supported addresses.
    pub contracts: Vec<EntryWithDelegation>,
    /// The fee recipient address.
    pub fee_recipient: Address,
    /// Quote related configuration.
    pub quote_config: QuoteConfig,
}
