use super::CoinKind;
use alloy::primitives::Address;
use serde::{Deserialize, Serialize};

/// Token type with its address, decimals and [`CoinKind`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    /// Token address.
    pub address: Address,
    /// Token decimals.
    pub decimals: u8,
    /// Coin kind.
    pub coin: CoinKind,
}

impl Token {
    /// Create a new instance of [`Self`].
    pub fn new(address: Address, decimals: u8, coin: CoinKind) -> Self {
        Self { address, decimals, coin }
    }
}
