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
    pub fn address(&self) -> Address {
        match self {
            AddressOrNative::Address(address) => *address,
            AddressOrNative::Native => Address::ZERO,
        }
    }

    /// Whether it is the native asset from a chain.
    pub fn is_native(&self) -> bool {
        matches!(self, Self::Native)
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

impl From<Address> for AddressOrNative {
    fn from(value: Address) -> Self {
        if value.is_zero() { Self::Native } else { Self::Address(value) }
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

impl AssetFilterItem {
    /// Create a new asset filter item for a fungible token (native or ERC20).
    pub fn fungible(asset: AddressOrNative) -> Self {
        Self {
            address: asset,
            asset_type: match asset {
                AddressOrNative::Native => AssetType::Native,
                AddressOrNative::Address(_) => AssetType::ERC20,
            },
        }
    }
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
    #[serde(with = "alloy::serde::quantity::vec")]
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
    /// Get a specific asset on the given chain.
    pub fn asset_on_chain(
        &self,
        chain: ChainId,
        asset_address: AddressOrNative,
    ) -> Option<&Asset7811> {
        self.0
            .get(&chain)
            .and_then(|assets| assets.iter().find(|asset| asset.address == asset_address))
    }

    /// Get the balance of a specific asset on the given chain.
    pub fn balance_on_chain(&self, chain: ChainId, asset_address: AddressOrNative) -> U256 {
        self.asset_on_chain(chain, asset_address).map(|asset| asset.balance).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::Address;

    #[test]
    fn test_get_assets_parameters_roundtrip() {
        let raw = r#"{"account":"0x0000000000000000000000000000000000000000","assetFilter":{},"assetTypeFilter":[],"chainFilter":["0x1"]}"#;
        let params = super::GetAssetsParameters {
            account: Address::ZERO,
            chain_filter: vec![1],
            ..Default::default()
        };

        let json = serde_json::to_string(&params).unwrap();
        assert_eq!(json, raw);
        let deserialized: super::GetAssetsParameters = serde_json::from_str(&json).unwrap();

        assert_eq!(params.account, deserialized.account);
        assert_eq!(params.chain_filter, deserialized.chain_filter);
    }
}
