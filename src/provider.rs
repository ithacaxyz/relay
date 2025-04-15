//! Alloy provider extensions.

use crate::op::{L1_BLOCK_CONTRACT, L1Block, L1BlockFees};
use alloy::{providers::Provider, transports::TransportResult};

/// Extension trait for [`Provider`] adding helpers for interacting with OP rollups.
pub trait ProviderExt: Provider {
    /// Heuristically determines whether this chain is an OP rollup.
    fn is_optimism(&self) -> impl Future<Output = TransportResult<bool>> + Send {
        async move {
            let chain_id = self.get_chain_id().await.unwrap();
            if alloy_chains::Chain::from(chain_id).is_optimism() {
                Ok(true)
            } else {
                Ok(!self.get_code_at(L1_BLOCK_CONTRACT).await?.is_empty())
            }
        }
    }

    /// Fetches [`L1BlockFees`] from the [`L1_BLOCK_CONTRACT`].
    fn fetch_l1_fees(&self) -> impl Future<Output = TransportResult<L1BlockFees>> + Send
    where
        Self: Sized,
    {
        async move { L1Block::new(L1_BLOCK_CONTRACT, self).fetch_fees().await }
    }
}

impl<T> ProviderExt for T where T: Provider {}
