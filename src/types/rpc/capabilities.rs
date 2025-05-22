use crate::{
    config::QuoteConfig,
    types::{Token, VersionedContracts},
};
use alloy::primitives::{Address, ChainId, map::HashMap};
use serde::{Deserialize, Serialize};

/// The Relay capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayCapabilities(
    #[serde(with = "alloy::serde::quantity::hashmap")] pub HashMap<ChainId, ChainCapabilities>,
);

impl RelayCapabilities {
    /// Returns a reference to a specific chain capabilities.
    ///
    /// # Panics
    /// It will panic if chain does not exist.
    pub fn chain(&self, chain_id: ChainId) -> &ChainCapabilities {
        self.0.get(&chain_id).as_ref().unwrap()
    }
}

/// Chain capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainCapabilities {
    /// The contracts of the relay.
    pub contracts: VersionedContracts,
    /// The fee configuration of the chain.
    pub fees: ChainFees,
}

impl ChainCapabilities {
    /// Whether it has the requested fee token.
    pub fn has_token(&self, address: &Address) -> bool {
        self.fees.tokens.iter().any(|t| t.address == *address)
    }
}
/// Chain fee settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainFees {
    /// The fee recipient address.
    pub recipient: Address,
    /// Quote related configuration.
    pub quote_config: QuoteConfig,
    /// Tokens the fees can be paid in.
    pub tokens: Vec<Token>,
}
