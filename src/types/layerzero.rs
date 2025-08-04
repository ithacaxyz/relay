//! LayerZero specific types

use crate::interop::settler::layerzero::{EndpointId, LZChainConfig};
use alloy::{
    primitives::{Address, ChainId, map::HashMap},
    providers::DynProvider,
};
use std::sync::Arc;

/// Chain configurations for LayerZero
#[derive(Debug, Clone)]
pub struct LZChainConfigs(Arc<HashMap<ChainId, LZChainConfig>>);

impl LZChainConfigs {
    /// Create new LZChainConfigs from components
    pub fn new(
        endpoint_ids: &HashMap<ChainId, EndpointId>,
        endpoint_addresses: &HashMap<ChainId, Address>,
        providers: &HashMap<ChainId, DynProvider>,
        settler_address: Address,
    ) -> Self {
        let configs: HashMap<ChainId, LZChainConfig> = endpoint_ids
            .iter()
            .filter_map(|(chain_id, endpoint_id)| {
                let endpoint_address = endpoint_addresses.get(chain_id)?;
                let provider = providers.get(chain_id)?;

                Some((
                    *chain_id,
                    LZChainConfig {
                        endpoint_id: *endpoint_id,
                        endpoint_address: *endpoint_address,
                        provider: provider.clone(),
                        settler_address,
                    },
                ))
            })
            .collect();

        Self(Arc::new(configs))
    }

    /// Get a chain config by chain ID
    pub fn get(&self, chain_id: &ChainId) -> Option<&LZChainConfig> {
        self.0.get(chain_id)
    }

    /// Iterate over all chain configs
    pub fn iter(&self) -> impl Iterator<Item = (&ChainId, &LZChainConfig)> {
        self.0.iter()
    }
}
