//! A collection of providers for different chains.

use alloy::{
    primitives::{ChainId, map::HashMap},
    providers::{DynProvider, Provider},
    transports::{RpcError, TransportErrorKind, TransportResult},
};

use crate::{
    config::TransactionServiceConfig,
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
    ) -> TransportResult<Self> {
        let chains = HashMap::from_iter(
            futures_util::future::try_join_all(providers.into_iter().map(|provider| async {
                let service = TransactionService::new(
                    provider.clone(),
                    tx_signers.clone(),
                    storage.clone(),
                    config.clone(),
                )
                .await;
                let transactions = service.handle();
                tokio::spawn(service);

                let chain_id = provider.get_chain_id().await?;
                Ok::<_, RpcError<TransportErrorKind>>((chain_id, Chain { provider, transactions }))
            }))
            .await?,
        );

        Ok(Self { chains })
    }

    /// Get a provider for a given chain ID.
    pub fn get(&self, chain_id: ChainId) -> Option<Chain> {
        self.chains.get(&chain_id).cloned()
    }

    /// Get the first provider in the collection.
    // NOTE: TEMPORARY PLEASE DELETE THIS AFTER https://github.com/ithacaxyz/relay/pull/331
    pub fn first(&self) -> Option<(&ChainId, &Chain)> {
        self.chains.iter().next()
    }
}

impl std::fmt::Debug for Chains {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Chains").field("providers", &self.chains.keys()).finish()
    }
}
