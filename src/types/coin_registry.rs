use super::CoinKind;
use alloy::primitives::{Address, ChainId, address};
use alloy_chains::{Chain, NamedChain};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{collections::HashMap, path::Path};

/// Maps [`ChainId`] and token addresses ([`CoinRegistryKey`]) to [`CoinKind`].
#[derive(Debug, Clone)]
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

    /// Load from a json file.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> eyre::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config = toml::from_str(&content)?;
        Ok(config)
    }

    /// Save to a json file.
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> eyre::Result<()> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

impl Default for CoinRegistry {
    fn default() -> Self {
        let ethereum: ChainId = Chain::mainnet().into();
        let op: ChainId = Chain::optimism_mainnet().into();
        let base: ChainId = Chain::base_mainnet().into();
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
                // USDT mappings
                ((ethereum, address!("dAC17F958D2ee523a2206206994597C13D831ec7").into()), usdt),
                ((op, address!("0xdAC17F958D2ee523a2206206994597C13D831ec7").into()), usdt),
                ((odyssey, address!("238c8CD93ee9F8c7Edf395548eF60c0d2e46665E").into()), usdt),
                ((odyssey, address!("706aa5c8e5cc2c67da21ee220718f6f6b154e75c").into()), usdt),
                // USDC mappings
                ((ethereum, address!("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").into()), usdc),
                ((base, address!("833589fCD6eDb6E08f4c7C32D4f71b54bdA02913").into()), usdc),
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
    pub token_address: Option<Address>,
}

impl From<(ChainId, Option<Address>)> for CoinRegistryKey {
    fn from(value: (ChainId, Option<Address>)) -> Self {
        CoinRegistryKey { chain: value.0, token_address: value.1 }
    }
}

/// Intermediate serde representation for a coin entry to get a nicer looking serialized output.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum CoinType {
    Native(CoinKind),
    Token(Address, CoinKind),
}

impl Serialize for CoinRegistry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut grouped: HashMap<String, Vec<CoinType>> = HashMap::new();
        for (CoinRegistryKey { chain, token_address }, &coin_kind) in self.iter() {
            let chain_key = chain.to_string();
            let entry = match token_address {
                None => CoinType::Native(coin_kind),
                Some(address) => CoinType::Token(*address, coin_kind),
            };
            grouped.entry(chain_key).or_default().push(entry);
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
        for (chain_str, entries) in grouped {
            let chain = chain_str.parse().map_err(serde::de::Error::custom)?;
            for entry in entries {
                match entry {
                    CoinType::Native(coin_kind) => {
                        map.insert((chain, None).into(), coin_kind);
                    }
                    CoinType::Token(address, coin_kind) => {
                        map.insert((chain, Some(address)).into(), coin_kind);
                    }
                }
            }
        }
        Ok(CoinRegistry(map))
    }
}
