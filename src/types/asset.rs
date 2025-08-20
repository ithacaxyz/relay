use std::collections::HashMap;

use alloy::primitives::Address;
use derive_more::{Display, FromStr};
use serde::{Deserialize, Serialize};

/// A unique ID for an asset.
#[derive(Debug, Display, Clone, Eq, PartialEq, FromStr, Hash, Serialize, Deserialize)]
pub struct AssetUid(String);

impl AssetUid {
    /// Create a new unique ID from a string.
    pub fn new(uid: String) -> Self {
        Self(uid)
    }

    /// Borrow the internal identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A collection of assets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assets(HashMap<AssetUid, AssetDescriptor>);

impl Assets {
    /// Create a new container.
    pub fn new(assets: HashMap<AssetUid, AssetDescriptor>) -> Self {
        Self(assets)
    }

    /// Get the native asset if it is defined.
    pub fn native(&self) -> Option<(&AssetUid, &AssetDescriptor)> {
        self.find_by_address(Address::ZERO)
    }

    /// Get an asset by its unique ID, if any.
    pub fn get(&self, uid: &AssetUid) -> Option<&AssetDescriptor> {
        self.0.get(uid)
    }

    /// Find an asset by address, if any.
    pub fn find_by_address(&self, address: Address) -> Option<(&AssetUid, &AssetDescriptor)> {
        self.0.iter().find(|(_, desc)| desc.address == address)
    }

    /// Iterate over all assets.
    pub fn iter(&self) -> impl Iterator<Item = (&AssetUid, &AssetDescriptor)> {
        self.0.iter()
    }

    /// Get assets relayable across chains.
    pub fn interop_tokens(&self) -> Vec<(AssetUid, AssetDescriptor)> {
        self.interop_iter().map(|(a, b)| (a.clone(), b.clone())).collect()
    }

    /// Iterate over all assets that are relayable across chains.
    pub fn interop_iter(&self) -> impl Iterator<Item = (&AssetUid, &AssetDescriptor)> {
        self.iter().filter(|(_, desc)| desc.interop)
    }

    /// Get assets accepted as fee tokens.
    pub fn fee_tokens(&self) -> Vec<(AssetUid, AssetDescriptor)> {
        self.fee_token_iter().map(|(a, b)| (a.clone(), b.clone())).collect()
    }

    /// Iterate over all assets that are accepted as fee tokens.
    pub fn fee_token_iter(&self) -> impl Iterator<Item = (&AssetUid, &AssetDescriptor)> {
        self.iter().filter(|(_, desc)| desc.fee_token)
    }
}

/// The description of a configured asset for a chain.
///
/// This is part of the response of `wallet_getCapabilities` and used in the
/// [`RelayConfig`](crate::config::RelayConfig).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetDescriptor {
    /// The address of the asset.
    pub address: Address,
    /// The number of decimals in the asset.
    ///
    /// Defaults to 18.
    #[serde(default = "default_decimals")]
    pub decimals: u8,
    /// Whether users can pay fees in this asset.
    #[serde(default, alias = "fee_token")]
    pub fee_token: bool,
    /// Whether this asset can be relayed across chains.
    #[serde(default)]
    pub interop: bool,
}

/// The default decimals for an asset.
fn default_decimals() -> u8 {
    18
}

/// Asset metadata
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AssetMetadata {
    /// Asset name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Asset symbol.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    /// TokenURI if it exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    /// Asset decimals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decimals: Option<u8>,
}

/// Asset price, including the currency the price is denominated in, this is currently always USD.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssetPrice {
    /// The currency
    currency: String,
    /// The price
    price: f64,
}

impl AssetPrice {
    /// Creates a new price, in USD, from the argument.
    pub fn from_price(price: f64) -> Self {
        Self { currency: "USD".to_string(), price }
    }
}

/// Asset metadata with price information
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssetMetadataWithPrice {
    /// Asset name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Asset symbol.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    /// TokenURI if it exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    /// Asset decimals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decimals: Option<u8>,
    /// Price information
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price: Option<AssetPrice>,
}

/// Asset type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AssetType {
    /// Native
    Native,
    /// ERC20.
    ERC20,
    /// ERC721.
    ERC721,
}

impl AssetType {
    /// Whether it is native.
    pub fn is_native(&self) -> bool {
        matches!(self, Self::Native)
    }

    /// Whether it is ERC20.
    pub fn is_erc20(&self) -> bool {
        matches!(self, Self::ERC20)
    }

    /// Whether it is erc721.
    pub fn is_erc721(&self) -> bool {
        matches!(self, Self::ERC721)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_asset_type() {
        let kind = AssetType::ERC20;
        let value = serde_json::to_string(&kind).unwrap();
        assert_eq!("\"erc20\"", value);
        let kind = serde_json::from_str::<AssetType>(&value).unwrap();
        assert_eq!(kind, AssetType::ERC20);
    }

    #[test]
    fn asset_descriptor_serde_roundtrip() {
        let json = r#"{
            "address": "0x0101010101010101010101010101010101010101",
            "decimals": 6,
            "feeToken": true,
            "interop": false
        }"#;

        let descriptor: AssetDescriptor = serde_json::from_str(json).unwrap();
        assert_eq!(descriptor.address, Address::from([1; 20]));
        assert_eq!(descriptor.decimals, 6);
        assert!(descriptor.fee_token);
        assert!(!descriptor.interop);

        // Roundtrip
        let serialized = serde_json::to_string(&descriptor).unwrap();
        let deserialized: AssetDescriptor = serde_json::from_str(&serialized).unwrap();
        assert_eq!(descriptor.address, deserialized.address);
        assert_eq!(descriptor.decimals, deserialized.decimals);
        assert_eq!(descriptor.fee_token, deserialized.fee_token);
        assert_eq!(descriptor.interop, deserialized.interop);

        let json = r#"{
            "address": "0x0101010101010101010101010101010101010101",
            "decimals": 6,
            "fee_token": true,
            "interop": false
        }"#;

        let descriptor_snake_case: AssetDescriptor = serde_json::from_str(json).unwrap();
        assert_eq!(descriptor, descriptor_snake_case);
    }
}
