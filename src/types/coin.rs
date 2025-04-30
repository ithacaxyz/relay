use super::{CoinRegistry, CoinRegistryKey};
use alloy::primitives::{Address, ChainId};
use serde::{Deserialize, Serialize};
use std::fmt::Display;

/// A coin price pair.
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct CoinPair {
    /// Numerator.
    pub from: CoinKind,
    /// Denominator.
    pub to: CoinKind,
}

impl CoinPair {
    /// Creates a list of ETH coin pairs from a [`CoinKind`] list.
    pub fn ethereum_pairs(coins: &[CoinKind]) -> Vec<Self> {
        coins.iter().map(|coin| CoinPair { from: *coin, to: CoinKind::ETH }).collect()
    }

    /// Returns the pair identifier.
    pub fn identifier(&self) -> String {
        format!("{}/{}", self.from, self.to)
    }
}

/// Chain, address and contract agonistic coins.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CoinKind {
    /// Ethereum
    ETH,
    /// USDT
    USDT,
    /// USDC
    USDC,
}

impl CoinKind {
    /// Get a list of [`Chain`] from [`self`].
    pub fn get_chains(&self, registry: &CoinRegistry) -> Vec<ChainId> {
        registry
            .iter()
            .filter(|(_, entry_coin)| *entry_coin == self)
            .map(|(key, _)| key.chain)
            .collect()
    }

    /// Get [`Address`] from a [`Chain`] and `self`.
    pub fn get_token_address(&self, registry: &CoinRegistry, chain: ChainId) -> Option<Address> {
        registry
            .iter()
            .find(|(entry_key, entry_coin)| {
                entry_key.chain == chain && *entry_coin == self && entry_key.token_address.is_some()
            })
            .map(|(key, _)| key.token_address.expect("qed"))
    }

    /// Whether this is ETH.
    pub fn is_eth(&self) -> bool {
        matches!(self, Self::ETH)
    }

    /// Get native [`CoinKind`] from [`Chain`].
    pub fn get_native(registry: &CoinRegistry, chain: ChainId) -> Option<Self> {
        registry.get(&CoinRegistryKey { chain, token_address: None }).copied()
    }

    /// Get [`CoinKind`] from a [`Chain`] and [`Address`].
    pub fn get_token(registry: &CoinRegistry, chain: ChainId, address: Address) -> Option<Self> {
        registry.get(&CoinRegistryKey { chain, token_address: Some(address) }).copied()
    }

    /// Returns the str identifier
    pub fn as_str(&self) -> &str {
        match self {
            CoinKind::ETH => "ETH",
            CoinKind::USDT => "USDT",
            CoinKind::USDC => "USDC",
        }
    }
}

impl Display for CoinKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
