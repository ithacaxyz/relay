use serde::{Deserialize, Serialize};

/// Asset metadata
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AssetMetadata {
    /// Asset name.
    pub name: Option<String>,
    /// Asset symbol.
    pub symbol: Option<String>,
    /// TokenURI if it exists.
    pub uri: Option<String>,
    /// Asset decimals.
    pub decimals: Option<u8>,
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
