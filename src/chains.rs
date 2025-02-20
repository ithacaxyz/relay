//! A collection of providers for different chains.

use alloy::{
    primitives::{ChainId, map::HashMap},
    providers::{DynProvider, Provider},
    transports::{RpcError, TransportErrorKind, TransportResult},
};

/// A collection of providers for different chains.
pub struct Chains {
    /// The providers for each chain.
    providers: HashMap<ChainId, DynProvider>,
}

impl Chains {
    /// Creates a new instance of [`Chains`].
    pub async fn new(providers: Vec<DynProvider>) -> TransportResult<Self> {
        let providers = HashMap::from_iter(
            futures_util::future::try_join_all(providers.into_iter().map(|provider| async move {
                Ok::<_, RpcError<TransportErrorKind>>((provider.get_chain_id().await?, provider))
            }))
            .await?,
        );

        Ok(Self { providers })
    }

    /// Get a provider for a given chain ID.
    pub fn get(&self, chain_id: ChainId) -> Option<DynProvider> {
        self.providers.get(&chain_id).cloned()
    }
}

impl std::fmt::Debug for Chains {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Chains").field("providers", &self.providers.keys()).finish()
    }
}
