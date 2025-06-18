//! A collection of providers for different chains.

use alloy::{
    primitives::{ChainId, map::HashMap},
    providers::{DynProvider, Provider},
};

use crate::{
    config::RelayConfig,
    provider::ProviderExt,
    signers::DynSigner,
    storage::RelayStorage,
    transactions::{
        InteropService, InteropServiceHandle, TransactionService, TransactionServiceHandle,
    },
};

/// A single supported chain.
#[derive(Debug, Clone)]
pub struct Chain {
    /// Provider for the chain.
    pub provider: DynProvider,
    /// Handle to the transaction service.
    pub transactions: TransactionServiceHandle,
    /// Whether this is an OP network.
    pub is_optimism: bool,
    /// The chain ID.
    pub chain_id: ChainId,
}

/// A collection of providers for different chains.
#[derive(Clone)]
pub struct Chains {
    /// The providers for each chain.
    chains: HashMap<ChainId, Chain>,
    /// Handle to the interop service.
    interop: InteropServiceHandle,
}

impl Chains {
    /// Creates a new instance of [`Chains`].
    pub async fn new(
        providers: Vec<DynProvider>,
        tx_signers: Vec<DynSigner>,
        storage: RelayStorage,
        config: &RelayConfig,
    ) -> eyre::Result<Self> {
        let chains = HashMap::from_iter(
            futures_util::future::try_join_all(providers.into_iter().map(|provider| async {
                let (service, handle) = TransactionService::new(
                    provider.clone(),
                    tx_signers.clone(),
                    storage.clone(),
                    config.transactions.clone(),
                )
                .await?;
                tokio::spawn(service);

                let chain_id = provider.get_chain_id().await?;
                let is_optimism = provider.is_optimism().await?;
                eyre::Ok((
                    chain_id,
                    Chain { provider, transactions: handle, is_optimism, chain_id },
                ))
            }))
            .await?,
        );

        let providers_with_chain =
            chains.iter().map(|(chain_id, chain)| (*chain_id, chain.provider.clone())).collect();
        let tx_handles: HashMap<ChainId, TransactionServiceHandle> = chains
            .iter()
            .map(|(chain_id, chain)| (*chain_id, chain.transactions.clone()))
            .collect();

        // Create and spawn the interop service
        let (interop_service, interop_handle) =
            InteropService::new(providers_with_chain, tx_handles, config.funder).await?;
        tokio::spawn(interop_service);

        Ok(Self { chains, interop: interop_handle })
    }

    /// Get a provider for a given chain ID.
    pub fn get(&self, chain_id: ChainId) -> Option<Chain> {
        self.chains.get(&chain_id).cloned()
    }

    /// Get an iterator over the supported chain IDs.
    pub fn chain_ids_iter(&self) -> impl Iterator<Item = &ChainId> {
        self.chains.keys()
    }

    /// Get the interop service handle.
    pub fn interop(&self) -> &InteropServiceHandle {
        &self.interop
    }
}

impl std::fmt::Debug for Chains {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Chains")
            .field("providers", &self.chains.keys())
            .field("interop", &self.interop)
            .finish()
    }
}
