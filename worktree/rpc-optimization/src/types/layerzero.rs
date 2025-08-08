//! LayerZero specific types

use crate::interop::{
    SettlementError,
    settler::layerzero::{
        EndpointId, LZChainConfig, contracts::IReceiveUln302, types::LayerZeroPacketInfo,
    },
};
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

    /// Returns corresponding [`LZChainConfig`] for the given chain id.
    pub fn ensure_chain_config(
        &self,
        chain_id: ChainId,
    ) -> Result<&LZChainConfig, SettlementError> {
        self.get(&chain_id).ok_or(SettlementError::UnsupportedChain(chain_id))
    }

    /// Checks if a LayerZero message is verified and available for execution.
    ///
    /// This checks if the ReceiveLib reports it as verifiable (DVN threshold met).
    ///
    /// Returns an [`SettlementError::UnsupportedChain`] error if no config for the destination
    /// chain exists.
    pub async fn is_message_available(
        &self,
        packet: &LayerZeroPacketInfo,
    ) -> Result<bool, SettlementError> {
        let dst_config = self.ensure_chain_config(packet.dst_chain_id)?;

        let receive_lib = IReceiveUln302::new(packet.receive_lib_address, &dst_config.provider);

        // Check if all required DVNs have verified.
        Ok(receive_lib
            .verifiable(packet.uln_config.clone(), packet.header_hash, packet.payload_hash)
            .call()
            .await?)
    }
}
