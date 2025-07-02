//! A collection of providers for different chains.

use alloy::{
    primitives::{ChainId, map::HashMap},
    providers::{DynProvider, Provider},
};

use crate::{
    config::TransactionServiceConfig,
    provider::ProviderExt,
    signers::DynSigner,
    storage::RelayStorage,
    transactions::{TransactionService, TransactionServiceHandle},
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

impl Chain {
    /// Returns the provider used to interact with this chain.
    pub const fn provider(&self) -> &DynProvider {
        &self.provider
    }

    /// Returns the chain id
    pub const fn id(&self) -> ChainId {
        self.chain_id
    }
}

/// A collection of providers for different chains.
#[derive(Clone)]
pub struct Chains {
    /// The providers for each chain.
    chains: HashMap<ChainId, Chain>,
}

impl Chains {
    /// Creates a new instance of [`Chains`].
    pub async fn new(
        providers: Vec<DynProvider>,
        tx_signers: Vec<DynSigner>,
        storage: RelayStorage,
        config: TransactionServiceConfig,
    ) -> eyre::Result<Self> {
        let chains = HashMap::from_iter(
            futures_util::future::try_join_all(providers.into_iter().map(|provider| async {
                let (service, handle) = TransactionService::new(
                    provider.clone(),
                    tx_signers.clone(),
                    storage.clone(),
                    config.clone(),
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

        Ok(Self { chains })
    }

    /// Get a provider for a given chain ID.
    pub fn get(&self, chain_id: ChainId) -> Option<Chain> {
        self.chains.get(&chain_id).cloned()
    }

    /// Returns an iterator over all installed [`Chain`]s.
    pub fn chains(&self) -> impl Iterator<Item = &Chain> {
        self.chains.values()
    }

    /// Get an iterator over the supported chain IDs.
    pub fn chain_ids_iter(&self) -> impl Iterator<Item = &ChainId> {
        self.chains.keys()
    }
}

impl std::fmt::Debug for Chains {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Chains").field("providers", &self.chains.keys()).finish()
    }
}
