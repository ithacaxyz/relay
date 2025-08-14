use crate::{
    config::QuoteConfig,
    types::{AssetDescriptor, AssetUid, VersionedContracts},
};
use alloy::primitives::{Address, ChainId, U256, map::HashMap};
use serde::{Deserialize, Serialize};

/// The Relay capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayCapabilities(
    #[serde(with = "alloy::serde::quantity::hashmap")] pub HashMap<ChainId, ChainCapabilities>,
);

impl RelayCapabilities {
    /// Returns a reference to a specific chain capabilities.
    ///
    /// # Panics
    /// It will panic if chain does not exist.
    pub fn chain(&self, chain_id: ChainId) -> &ChainCapabilities {
        self.0.get(&chain_id).as_ref().unwrap()
    }
}

/// Chain capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainCapabilities {
    /// The contracts of the relay.
    pub contracts: VersionedContracts,
    /// The fee configuration of the chain.
    pub fees: ChainFees,
}

/// Chain fee settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainFees {
    /// The fee recipient address.
    pub recipient: Address,
    /// Quote related configuration.
    pub quote_config: QuoteConfig,
    /// Tokens the fees can be paid in.
    pub tokens: Vec<ChainFeeToken>,
}

/// A wrapper around [`AssetUid`] and [`AssetDescriptor`] for [`ChainFees`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainFeeToken {
    /// The asset unique ID.
    pub uid: AssetUid,
    /// The asset.
    #[serde(flatten)]
    pub asset: AssetDescriptor,
    /// The symbol of the asset if we could resolve it, otherwise `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    /// Rate of 1 whole token against the native chain token, expressed in the native token's
    /// smallest indivisible unit.
    ///
    /// # Examples
    /// - USDC decimals: 6
    /// - ETH decimals: 18
    ///
    /// 1. **USDC on Ethereum**
    ///    - 1 USDC = 0.000628 ETH ⇒   `native_rate = 0.000628 * 10^18 = 628_000_000_000_000 Wei`
    /// 2. **Stablecoin chain where USDC _is_ the native token**
    ///    - 1 USDC = 1 USDC ⇒   `native_rate = 1 * 10^6 = 1_000_000`
    #[serde(alias = "native_rate")]
    pub native_rate: Option<U256>,
}

impl ChainFeeToken {
    /// Create a new `ChainFeeToken`.
    pub fn new(
        uid: AssetUid,
        asset: AssetDescriptor,
        symbol: Option<String>,
        native_rate: Option<U256>,
    ) -> Self {
        Self { uid, asset, symbol, native_rate }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_fee_token_serde_roundtrip() {
        let json = r#"{
            "uid": "usdc",
            "address": "0x0101010101010101010101010101010101010101",
            "decimals": 6,
            "feeToken": true,
            "symbol": "USDC",
            "nativeRate": "0x23b4a5a70d000"
        }"#;

        let token: ChainFeeToken = serde_json::from_str(json).unwrap();
        assert_eq!(token.uid.as_str(), "usdc");
        assert_eq!(token.asset.address, Address::from([1; 20]));
        assert_eq!(token.asset.decimals, 6);
        assert!(token.asset.fee_token);
        assert_eq!(token.symbol, Some("USDC".to_string()));
        assert_eq!(token.native_rate, Some(U256::from(628140484382720u64)));

        // Roundtrip
        let serialized = serde_json::to_string(&token).unwrap();
        let deserialized: ChainFeeToken = serde_json::from_str(&serialized).unwrap();
        assert_eq!(token.uid.as_str(), deserialized.uid.as_str());
        assert_eq!(token.native_rate, deserialized.native_rate);
    }
}
