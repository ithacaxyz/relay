use alloy::primitives::{address, Address};
use alloy_chains::Chain;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::LazyLock};

/// Global map from ([`Chain`], Option<[`Address`]>) to [`CoinKind`].
///
/// A (chain, none) refers to native chain coins. eg. Ethereum.
static COINS_CONFIG: LazyLock<HashMap<(Chain, Option<Address>), CoinKind>> = LazyLock::new(|| {
    // todo: read from file
    let mut coin_map = HashMap::new();

    // ETH
    {
        coin_map.insert((Chain::mainnet(), None), CoinKind::ETH);
        coin_map.insert((Chain::optimism_mainnet(), None), CoinKind::ETH);
        coin_map.insert((Chain::base_mainnet(), None), CoinKind::ETH);
    }

    // USDT
    {
        let addresses = [
            (Chain::mainnet(), address!("dAC17F958D2ee523a2206206994597C13D831ec7")),
            (Chain::optimism_mainnet(), address!("0xdAC17F958D2ee523a2206206994597C13D831ec7")),
        ];
        for (chain, address) in addresses {
            coin_map.insert((chain, Some(address)), CoinKind::USDT);
        }
    }

    // USDC
    {
        let addresses = [
            (Chain::mainnet(), address!("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")),
            (Chain::base_mainnet(), address!("833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")),
        ];
        for (chain, address) in addresses {
            coin_map.insert((chain, Some(address)), CoinKind::USDC);
        }
    }

    coin_map
});

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
}

/// Chain and address agonistic coins.
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
    pub fn get_chains(&self) -> Vec<Chain> {
        COINS_CONFIG
            .iter()
            .filter(|((_, _), entry_coin)| *entry_coin == self)
            .map(|((chain, _), _)| *chain)
            .collect()
    }

    /// Get [`Address`] from a [`Chain`] and `self`.
    pub fn get_token_address(&self, chain: Chain) -> Option<Address> {
        COINS_CONFIG
            .iter()
            .find(|((entry_chain, address), entry_coin)| {
                *entry_chain == chain && *entry_coin == self && address.is_some()
            })
            .map(|((_, address), _)| address.expect("qed"))
    }

    /// Whether this is ETH.
    pub fn is_eth(&self) -> bool {
        matches!(self, Self::ETH)
    }

    /// Get native [`CoinKind`] from [`Chain`].
    pub fn get_native(chain: Chain) -> Option<Self> {
        COINS_CONFIG.get(&(chain, None)).copied()
    }

    /// Get [`CoinKind`] from a [`Chain`] and [`Address`].
    pub fn get_token(chain: Chain, address: Address) -> Option<Self> {
        COINS_CONFIG.get(&(chain, Some(address))).copied()
    }
}
