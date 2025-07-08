use super::{Asset, CoinKind};
use alloy::primitives::{Address, ChainId, address};
use alloy_chains::{Chain, NamedChain};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{collections::HashMap, path::Path};

/// Maps [`ChainId`] and token addresses ([`CoinRegistryKey`]) to [`CoinKind`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinRegistry(HashMap<CoinRegistryKey, CoinKind>);

impl CoinRegistry {
    /// Extends inner registry with more entries.
    pub fn extend<I>(&mut self, registry: I)
    where
        I: IntoIterator<Item = ((ChainId, Option<Address>), CoinKind)>,
    {
        self.0.extend(registry.into_iter().map(|(k, v)| (k.into(), v)));
    }

    /// Returns [`CoinKind`] corresponding to [`CoinRegistryKey`].
    pub fn get(&self, key: &CoinRegistryKey) -> Option<&CoinKind> {
        self.0.get(key)
    }

    /// Returns an iterator over all pairs ([`CoinRegistryKey`], [`CoinKind`]).
    pub fn iter(&self) -> impl Iterator<Item = (&CoinRegistryKey, &CoinKind)> {
        self.0.iter()
    }

    /// Returns all equivalent coins on `target_chain`, given a `source_chain` and
    /// `source_asset`.
    ///
    /// A none `source_asset` represents the source chain native asset.
    pub fn get_from_other_chain(
        &self,
        source_chain: ChainId,
        source_asset: Option<Address>,
        target_chain: ChainId,
    ) -> Vec<Asset> {
        let Some(source_kind) = self.get(&(source_chain, source_asset).into()) else {
            return vec![];
        };

        self.iter()
            .filter(|(key, kind)| *kind == source_kind && key.chain == target_chain)
            .map(|(key, _)| Asset::from_address(key.address))
            .collect()
    }

    /// Load from a YAML file.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> eyre::Result<Self> {
        let file = std::fs::File::open(path)?;
        let config = serde_yaml::from_reader(&file)?;
        Ok(config)
    }

    /// Save to a YAML file.
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> eyre::Result<()> {
        let content = serde_yaml::to_string(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Returns the address of a coin on a chain.
    ///
    /// If the coin is native, returns `None`.
    pub fn address(&self, kind: CoinKind, chain: ChainId) -> Option<Option<Address>> {
        self.iter().find(|(k, v)| **v == kind && k.chain == chain).map(|(k, _)| k.address)
    }

    /// Retains only the entries for which the predicate returns true.
    pub fn retain(&mut self, f: impl Fn(&CoinRegistryKey, &CoinKind) -> bool) {
        self.0.retain(|k, v| f(k, v));
    }
}

impl Default for CoinRegistry {
    fn default() -> Self {
        let ethereum: ChainId = Chain::mainnet().into();
        let op: ChainId = Chain::optimism_mainnet().into();
        let base: ChainId = Chain::base_mainnet().into();
        let arbitrum: ChainId = Chain::arbitrum_mainnet().into();
        let odyssey: ChainId = NamedChain::Odyssey.into();

        let eth = CoinKind::ETH;
        let usdt = CoinKind::USDT;
        let usdc = CoinKind::USDC;

        Self(
            [
                // ETH mappings
                ((ethereum, None), eth),
                ((op, None), eth),
                ((base, None), eth),
                ((odyssey, None), eth),
                ((arbitrum, None), eth),
                // USDT mappings
                ((ethereum, address!("0xdAC17F958D2ee523a2206206994597C13D831ec7").into()), usdt),
                ((op, address!("0xdAC17F958D2ee523a2206206994597C13D831ec7").into()), usdt),
                ((odyssey, address!("0x238c8CD93ee9F8c7Edf395548eF60c0d2e46665E").into()), usdt),
                ((odyssey, address!("0x706aa5c8e5cc2c67da21ee220718f6f6b154e75c").into()), usdt),
                // USDC mappings
                ((ethereum, address!("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").into()), usdc),
                ((base, address!("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913").into()), usdc),
                ((arbitrum, address!("0xaf88d065e77c8cC2239327C5EDb3A432268e5831").into()), usdc),
            ]
            .into_iter()
            .map(|(k, v)| (k.into(), v))
            .collect(),
        )
    }
}

/// Key type of [`CoinRegistry`].
///
/// A `(chain, None)` refers to native chain coins. eg. ETH.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CoinRegistryKey {
    /// Chain.
    pub chain: ChainId,
    /// Address in case it's a deployed token.
    pub address: Option<Address>,
}

impl From<(ChainId, Option<Address>)> for CoinRegistryKey {
    fn from(value: (ChainId, Option<Address>)) -> Self {
        CoinRegistryKey { chain: value.0, address: value.1 }
    }
}

/// Intermediate serde representation for a coin entry to get a nicer looking serialized output.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum CoinType {
    Token { address: Address, kind: CoinKind },
    Native { kind: CoinKind },
}

impl Serialize for CoinRegistry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut grouped: HashMap<String, Vec<CoinType>> = HashMap::new();
        for (CoinRegistryKey { chain, address }, &coin_kind) in self.iter() {
            let chain = chain.to_string();
            let entry = match address {
                None => CoinType::Native { kind: coin_kind },
                Some(address) => CoinType::Token { address: *address, kind: coin_kind },
            };
            grouped.entry(chain).or_default().push(entry);
        }
        grouped.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CoinRegistry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let grouped: HashMap<String, Vec<CoinType>> = HashMap::deserialize(deserializer)?;
        let mut map = HashMap::new();
        for (chain, entries) in grouped {
            let chain = chain.parse().map_err(serde::de::Error::custom)?;
            for entry in entries {
                match entry {
                    CoinType::Native { kind } => {
                        map.insert((chain, None).into(), kind);
                    }
                    CoinType::Token { address, kind } => {
                        map.insert((chain, Some(address)).into(), kind);
                    }
                }
            }
        }
        Ok(CoinRegistry(map))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let default_registry = CoinRegistry::default();

        let file = tempfile::NamedTempFile::new().unwrap();
        default_registry.save_to_file(file.path()).unwrap();

        assert_eq!(default_registry, CoinRegistry::load_from_file(file.path()).unwrap());
    }

    #[test]
    fn test_get_from_other_chain() {
        let registry = CoinRegistry::default();

        // Test ETH equivalents
        let ethereum: ChainId = Chain::mainnet().into();
        let odyssey: ChainId = NamedChain::Odyssey.into();

        // ETH on mainnet -> ETH on odyssey
        let eth_on_odyssey = registry.get_from_other_chain(ethereum, None, odyssey);
        assert_eq!(eth_on_odyssey.len(), 1);
        assert_eq!(eth_on_odyssey[0], super::super::Asset::Native);

        // USDT on ethereum -> USDT on odyssey
        let usdt_address = address!("0xdAC17F958D2ee523a2206206994597C13D831ec7");
        let usdt_on_odyssey = registry.get_from_other_chain(ethereum, Some(usdt_address), odyssey);
        assert_eq!(usdt_on_odyssey.len(), 2); // There are 2 USDT addresses on odyssey

        // Non-existent token
        let random_address = address!("0x0000000000000000000000000000000000000000");
        let not_found = registry.get_from_other_chain(ethereum, Some(random_address), odyssey);
        assert_eq!(not_found.len(), 0);
    }
}
