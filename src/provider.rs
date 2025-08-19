//! Alloy provider extensions.

use crate::estimation::{arb::ARB_NODE_INTERFACE_ADDRESS, op::OP_GAS_PRICE_ORACLE_ADDRESS};
use alloy::{providers::Provider, transports::TransportResult};

/// Extension trait for [`Provider`] adding helpers for interacting with rollups.
pub trait ProviderExt: Provider {
    /// Heuristically determines whether this chain is an OP rollup.
    fn is_optimism(&self) -> impl Future<Output = TransportResult<bool>> + Send {
        async move {
            let chain_id = self.get_chain_id().await.unwrap();
            if alloy_chains::Chain::from(chain_id).is_optimism() {
                Ok(true)
            } else {
                Ok(!self.get_code_at(OP_GAS_PRICE_ORACLE_ADDRESS).await?.is_empty())
            }
        }
    }

    /// Heuristically determines whether this chain is an Arbitrum rollup.
    fn is_arbitrum(&self) -> impl Future<Output = TransportResult<bool>> + Send {
        async move {
            let chain_id = self.get_chain_id().await.unwrap();
            if alloy_chains::Chain::from(chain_id).is_arbitrum() {
                Ok(true)
            } else {
                Ok(!self.get_code_at(ARB_NODE_INTERFACE_ADDRESS).await?.is_empty())
            }
        }
    }
}

impl<T> ProviderExt for T where T: Provider {}
