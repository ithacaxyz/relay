use alloy::primitives::{Address, address, aliases::I512};
use serde::{Deserialize, Serialize};

/// Net flow per account and asset based on simulated execution logs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AssetDiffs(pub Vec<(Address, Vec<AssetDiff>)>);

/// Asset with metadata and value diff.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AssetDiff {
    /// Asset address. `None` represents the native token.
    pub address: Option<Address>,
    /// Asset name.
    pub name: Option<String>,
    /// Asset symbol.
    pub symbol: Option<String>,
    /// Asset decimals.
    pub decimals: Option<u8>,
    /// Value diff.
    pub value: I512,
}

/// Asset coming from `eth_simulateV1` transfer logs.
///
/// Note: Token variant might not be ERC20.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Asset {
    /// Native asset.
    Native,
    /// Token asset.
    Token(Address),
}

impl Asset {
    /// Whether it is the native asset from a chain.
    pub fn is_native(&self) -> bool {
        matches!(self, Self::Native)
    }

    /// Returns the address
    ///
    /// # Panics
    /// It will panic if self is of the native variant.
    pub fn address(&self) -> Address {
        match self {
            Asset::Native => panic!("only token assets can return an address"),
            Asset::Token(address) => *address,
        }
    }
}

impl From<Address> for Asset {
    fn from(asset: Address) -> Self {
        // 0xee..ee is how `eth_simulateV1` represents the native asset.
        if asset == address!("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee") {
            Asset::Native
        } else {
            Asset::Token(asset)
        }
    }
}

/// Represents metadata for an asset.
#[derive(Debug, Clone)]
pub struct AssetWithInfo {
    /// Asset.
    pub asset: Asset,
    /// Name.
    pub name: Option<String>,
    /// Symbol.
    pub symbol: Option<String>,
    /// Decimals.
    pub decimals: Option<u8>,
}
