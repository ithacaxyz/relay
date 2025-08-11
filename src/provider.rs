//! Alloy provider extensions and caching wrappers.

use crate::{
    cache::RpcCache,
    op::{OP_FEE_ORACLE_CONTRACT, OpL1FeeOracle},
};
use alloy::{
    primitives::{Address, Bytes, U256},
    providers::Provider,
    transports::{TransportErrorKind, TransportResult},
};
use std::sync::Arc;
use tracing::debug;

/// Extension trait for [`Provider`] adding helpers for interacting with OP rollups.
pub trait ProviderExt: Provider {
    /// Heuristically determines whether this chain is an OP rollup.
    fn is_optimism(&self) -> impl Future<Output = TransportResult<bool>> + Send {
        async move {
            let chain_id = self.get_chain_id().await?;
            if alloy_chains::Chain::from(chain_id).is_optimism() {
                Ok(true)
            } else {
                Ok(!self.get_code_at(OP_FEE_ORACLE_CONTRACT).await?.is_empty())
            }
        }
    }

    /// Estimates L1 DA fee for a given encoded transaction by using [`OpL1FeeOracle`].
    fn estimate_l1_fee(
        &self,
        encoded_tx: Bytes,
    ) -> impl Future<Output = TransportResult<U256>> + Send
    where
        Self: Sized,
    {
        async move {
            OpL1FeeOracle::new(OP_FEE_ORACLE_CONTRACT, self)
                .getL1Fee(encoded_tx)
                .call()
                .await
                .map_err(TransportErrorKind::custom)
        }
    }
}

impl<T> ProviderExt for T where T: Provider {}

/// A caching wrapper around an Alloy provider to reduce redundant RPC calls.
///
/// This wrapper implements the following caching strategies:
/// - Static caches for values that never change (chain_id, delegation)
#[derive(Debug, Clone)]
pub struct CachedProvider<P> {
    /// The underlying provider
    inner: P,
    /// Shared cache instance
    cache: Arc<RpcCache>,
}

impl<P> CachedProvider<P> {
    /// Create a new cached provider wrapper.
    pub fn new(provider: P, cache: Arc<RpcCache>) -> Self {
        Self { inner: provider, cache }
    }

    /// Get the cache instance.
    pub fn cache(&self) -> &Arc<RpcCache> {
        &self.cache
    }
}

impl<P> CachedProvider<P>
where
    P: Provider + Send + Sync,
{
    /// Get contract code with long-term caching.
    pub async fn get_code_at_cached(&self, address: Address) -> TransportResult<Bytes> {
        // Check cache first
        if let Some(cached_code) = self.cache.get_code(&address) {
            return Ok(cached_code);
        }

        // Cache miss - fetch from provider
        debug!(address = %address, "Code cache MISS - fetching from provider");
        let code = self.inner.get_code_at(address).await?;
        self.cache.set_code(address, code.clone());

        Ok(code)
    }
}
