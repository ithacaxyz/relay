//! A collection of providers for different chains.

use alloy::{
    primitives::{ChainId, map::HashMap},
    providers::{DynProvider, Provider},
};
use tracing::{info, warn};

use crate::{
    config::RelayConfig,
    liquidity::{
        LiquidityTracker, RebalanceService,
        bridge::{BinanceBridge, Bridge, SimpleBridge},
    },
    provider::ProviderExt,
    signers::DynSigner,
    storage::RelayStorage,
    transactions::{
        InteropService, InteropServiceHandle, TransactionService, TransactionServiceHandle,
    },
    types::FeeTokens,
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
    /// Handle to the interop service.
    interop: InteropServiceHandle,
}

impl Chains {
    /// Creates a new instance of [`Chains`].
    pub async fn new(
        providers: Vec<DynProvider>,
        tx_signers: Vec<DynSigner>,
        storage: RelayStorage,
        fee_tokens: &FeeTokens,
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

        let providers_with_chain: HashMap<_, _> =
            chains.iter().map(|(chain_id, chain)| (*chain_id, chain.provider.clone())).collect();
        let tx_handles: HashMap<ChainId, TransactionServiceHandle> = chains
            .iter()
            .map(|(chain_id, chain)| (*chain_id, chain.transactions.clone()))
            .collect();

        let liquidity_tracker =
            LiquidityTracker::new(providers_with_chain.clone(), config.funder, storage.clone());

        if let Some(rebalance_config) = &config.chain.rebalance_service {
            let funder_owner = DynSigner::from_raw(&rebalance_config.funder_owner_key).await?;

            let mut bridges: Vec<Box<dyn Bridge>> = Vec::new();

            if let Some(binance) = &rebalance_config.binance {
                bridges.push(Box::new(
                    BinanceBridge::new(
                        providers_with_chain.clone(),
                        tx_handles.clone(),
                        binance.clone(),
                        fee_tokens,
                        storage.clone(),
                        config.funder,
                        funder_owner.clone(),
                    )
                    .await?,
                ));
            }

            if let Some(simple) = &rebalance_config.simple {
                warn!("Enabling SimpleBridge. Should not be used in production!");

                bridges.push(Box::new(
                    SimpleBridge::new(
                        providers_with_chain.clone(),
                        tx_handles.clone(),
                        simple.clone(),
                        config.funder,
                        storage.clone(),
                        funder_owner.clone(),
                    )
                    .await?,
                ));
            }

            info!(bridges=?bridges.iter().map(|b| b.id()).collect::<Vec<_>>(), "Launching interop service");

            let service = RebalanceService::new(fee_tokens, liquidity_tracker.clone(), bridges);
            tokio::spawn(service.into_future().await?);
        }

        // Create and spawn the interop service
        let (interop_service, interop_handle) =
            InteropService::new(tx_handles, liquidity_tracker.clone(), config.interop.clone())
                .await?;

        tokio::spawn(interop_service);

        Ok(Self { chains, interop: interop_handle })
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
