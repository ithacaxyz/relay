//! RPC account-related request and response types.

use alloy::primitives::{Address, ChainId, U256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::types::{Asset, AssetMetadata, AssetType};

/// Address-based asset or native.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(untagged)]
pub enum AddressOrNative {
    /// Address.
    Address(Address),
    /// The special keyword `"native"`.
    #[serde(rename = "native")]
    Native,
}

impl AddressOrNative {
    /// Returns the address
    ///
    /// # Panics
    /// It will panic if self is of the native variant.
    pub fn address(&self) -> Address {
        match self {
            AddressOrNative::Address(address) => *address,
            AddressOrNative::Native => panic!(),
        }
    }
}

impl From<AddressOrNative> for Asset {
    fn from(value: AddressOrNative) -> Self {
        match value {
            AddressOrNative::Address(address) => Asset::Token(address),
            AddressOrNative::Native => Asset::Native,
        }
    }
}

/// One item inside each vector that lives under the per-chain key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetFilterItem {
    /// Address of the asset if not native.
    pub address: AddressOrNative,
    /// Asset type.
    #[serde(rename = "type")]
    pub asset_type: AssetType,
}

/// Request parameters for `wallet_getAssets`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GetAssetsParameters {
    /// Address of the EOA to query.
    pub account: Address,
    /// Optional per-chain asset filter. Overrides other filters.
    #[serde(default, with = "alloy::serde::quantity::hashmap")]
    pub asset_filter: HashMap<ChainId, Vec<AssetFilterItem>>,
    /// Restrict results to these asset types.
    #[serde(default)]
    pub asset_type_filter: Vec<AssetType>,
    /// Restrict results to these chains.
    #[serde(default)]
    pub chain_filter: Vec<ChainId>,
}

impl GetAssetsParameters {
    /// Generates parameters to get assets eoa on all chains.
    pub fn eoa(account: Address) -> Self {
        Self { account, ..Default::default() }
    }
}

/// Asset as described on ERC7811.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Asset7811 {
    /// Address or native
    pub address: AddressOrNative,
    /// Balance in the smallest unit.
    pub balance: U256,
    /// Native, ERC721 or ERC20
    #[serde(rename = "type")]
    pub asset_type: AssetType,
    /// Asset metadata.
    #[serde(default)]
    pub metadata: Option<AssetMetadata>,
}

/// Response for `wallet_getAssets`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GetAssetsResponse(
    #[serde(with = "alloy::serde::quantity::hashmap")] pub HashMap<ChainId, Vec<Asset7811>>,
);

impl GetAssetsResponse {
    /// Generates a list of chain and amount tuples that fund a target chain operation.
    ///
    /// If it returns None, there were not enough funds across all chains.
    /// If Some(empty), destination chain does not require any funding from other chains..
    pub fn find_funding_chains(
        &self,
        target_chain: ChainId,
        asset: AddressOrNative,
        amount: U256,
    ) -> Option<Vec<(ChainId, U256)>> {
        let existing = self
            .0
            .get(&target_chain)
            .and_then(|assets| assets.iter().find(|a| a.address == asset).map(|a| a.balance))
            .unwrap_or(U256::ZERO);

        let mut remaining = if existing >= amount { U256::ZERO } else { amount - existing };

        if remaining.is_zero() {
            return Some(vec![]);
        }

        // collect (chain, balance) for all other chains that have >0 balance
        let mut sources: Vec<(ChainId, U256)> = self
            .0
            .iter()
            .filter_map(|(&chain, assets)| {
                if chain == target_chain {
                    return None;
                }
                let balance = assets
                    .iter()
                    .find(|a| a.address == asset)
                    .map(|a| a.balance)
                    .unwrap_or(U256::ZERO);
                if balance.is_zero() { None } else { Some((chain, balance)) }
            })
            .collect();

        // highest balances first
        sources.sort_unstable_by(|a, b| b.1.cmp(&a.1));

        let mut plan = Vec::new();
        for (chain, balance) in sources {
            if remaining.is_zero() {
                break;
            }
            let take = if balance >= remaining { remaining } else { balance };
            plan.push((chain, take));
            remaining -= take;
        }

        if remaining.is_zero() {
            return Some(plan);
        }

        None
    }
}
