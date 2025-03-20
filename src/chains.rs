//! A collection of providers for different chains.

use alloy::{
    primitives::{ChainId, map::HashMap},
    providers::{DynProvider, Provider},
    transports::{RpcError, TransportErrorKind, TransportResult},
};

use crate::{
    signers::DynSigner,
    storage::RelayStorage,
    transactions::{Signer, TransactionService, TransactionServiceHandle},
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
    ) -> TransportResult<Self> {
        let chains = HashMap::from_iter(
            futures_util::future::try_join_all(providers.into_iter().map(|provider| async {
                let signers =
                    futures_util::future::try_join_all(tx_signers.clone().into_iter().map(
                        |tx_signer| Signer::spawn(provider.clone(), tx_signer, storage.clone()),
                    ))
                    .await?;

                let transactions = TransactionService::spawn(signers);

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
}

impl std::fmt::Debug for Chains {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Chains").field("providers", &self.chains.keys()).finish()
    }
}
