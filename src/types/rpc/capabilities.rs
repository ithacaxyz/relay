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
pub struct ChainFeeToken {
    /// The asset unique ID.
    pub uid: AssetUid,
    /// The asset.
    #[serde(flatten)]
    pub asset: AssetDescriptor,
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
    pub native_rate: Option<U256>,
}

impl ChainFeeToken {
    /// Create a new `ChainFeeToken`.
    pub fn new(uid: AssetUid, asset: AssetDescriptor, native_rate: Option<U256>) -> Self {
        Self { uid, asset, native_rate }
    }
}
