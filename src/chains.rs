//! A collection of providers for different chains.

use std::str::FromStr;

use alloy::{
    primitives::{Address, ChainId, map::HashMap},
    providers::{DynProvider, Provider, ProviderBuilder},
    rpc::client::{BuiltInConnectionString, ClientBuilder},
    transports::layers::RetryBackoffLayer,
};
use tracing::{info, warn};
use url::Url;

use crate::{
    config::{FeeConfig, RelayConfig, SimMode},
    constants::DEFAULT_POLL_INTERVAL,
    error::RelayError,
    interop::SettlementError,
    liquidity::{
        LiquidityTracker, RebalanceService,
        bridge::{BinanceBridge, Bridge, SimpleBridge},
    },
    metrics::TraceLayer,
    signers::DynSigner,
    storage::RelayStorage,
    transactions::{
        InteropService, InteropServiceHandle, TransactionService, TransactionServiceHandle,
    },
    transport::{SequencerLayer, create_transport},
    types::{AssetDescriptor, AssetUid, Assets},
};

/// [`RetryBackoffLayer`] used for chain providers.
///
/// We are allowing max 10 retries with a backoff of 800ms. The CU/s is set to max value to avoid
/// any throttling.
pub const RETRY_LAYER: RetryBackoffLayer = RetryBackoffLayer::new(10, 800, u64::MAX);

/// A single supported chain.
#[derive(Debug, Clone)]
pub struct Chain {
    /// Provider for the chain.
    provider: DynProvider,
    /// Handle to the transaction service.
    transactions: TransactionServiceHandle,
    /// The chain.
    chain: alloy_chains::Chain,
    /// The symbol of the native asset.
    native_symbol: Option<String>,
    /// The supported assets on the chain.
    assets: Assets,
    /// The simulation mode this chain supports
    sim_mode: SimMode,
    /// The fee settings for this particular chain
    fees: FeeConfig,
    /// The active signers for this chain.
    signers: Vec<DynSigner>,
    /// The settler address for this chain (if any).
    settler_address: Option<Address>,
}

impl Chain {
    /// Returns the provider used to interact with this chain.
    pub const fn provider(&self) -> &DynProvider {
        &self.provider
    }

    /// Returns the chain id
    pub const fn id(&self) -> ChainId {
        self.chain.id()
    }

    /// Returns the [`alloy_chains::Chain`]
    pub const fn chain(&self) -> &alloy_chains::Chain {
        &self.chain
    }

    /// Returns the native symbol of the chain.
    pub fn native_symbol(&self) -> Option<&str> {
        self.native_symbol.as_deref()
    }

    /// Returns the assets on the chain.
    pub const fn assets(&self) -> &Assets {
        &self.assets
    }

    /// Whether this is an OP Stack chain.
    pub const fn is_optimism(&self) -> bool {
        self.chain.is_optimism()
    }

    /// Whether this is an Arbitrum chain.
    pub const fn is_arbitrum(&self) -> bool {
        self.chain.is_arbitrum()
    }

    /// Returns access to the [`TransactionService`] via its handle.
    pub const fn transactions(&self) -> &TransactionServiceHandle {
        &self.transactions
    }

    /// Returns the simulation mode [`SimMode`] that should be used when simulating calls.
    pub const fn sim_mode(&self) -> SimMode {
        self.sim_mode
    }

    /// Returns the [`FeeConfig`] for this chain.
    pub const fn fee_config(&self) -> &FeeConfig {
        &self.fees
    }

    /// Returns an iterator over the signer addresses used by this chain.
    pub fn signer_addresses(&self) -> impl Iterator<Item = Address> {
        self.signers.iter().map(|s| s.address())
    }

    /// Returns how many signers are configured for this chain.
    pub fn signers_count(&self) -> usize {
        self.signers.len()
    }

    /// Returns the settler address for this chain (if any).
    pub const fn settler_address(&self) -> Option<Address> {
        self.settler_address
    }
}

/// A collection of providers for different chains.
#[derive(Clone)]
pub struct Chains {
    /// The providers for each chain.
    chains: HashMap<ChainId, Chain>,
    /// Handle to the interop service.
    interop: Option<InteropServiceHandle>,
}

impl Chains {
    /// Creates a new instance of [`Chains`].
    pub async fn new(
        tx_signers: Vec<DynSigner>,
        storage: RelayStorage,
        config: &RelayConfig,
    ) -> eyre::Result<Self> {
        let chains = HashMap::from_iter(
            futures_util::future::try_join_all(config.chains.iter().map(async |(chain, desc)| {
                // Enforce WebSocket endpoints since we need to subscribe to logs in the interop
                // service
                if config.interop.is_some()
                    && !desc.endpoint.as_str().starts_with("ws://")
                    && !desc.endpoint.as_str().starts_with("wss://")
                {
                    eyre::bail!(
                        "All endpoints must use WebSocket (ws:// or wss://). Got: {}",
                        desc.endpoint
                    );
                }

                // Only take as many signers as we need for this chain
                let chain_signers =
                    tx_signers.iter().take(desc.signers.num_signers).cloned().collect::<Vec<_>>();

                if chain_signers.is_empty() {
                    eyre::bail!("No signers configured for chain {chain}");
                }

                info!(
                    "Using [{}] signers for chain {chain}: {:?}",
                    desc.signers.num_signers,
                    chain_signers.iter().map(|s| s.address()).collect::<Vec<_>>()
                );

                let provider =
                    try_build_provider(chain.id(), &desc.endpoint, desc.sequencer.as_ref()).await?;
                let (service, handle) = TransactionService::new(
                    provider.clone(),
                    desc.flashblocks.as_ref(),
                    chain_signers.clone(),
                    storage.clone(),
                    config.transactions.clone(),
                    config.funder,
                    desc.fees.clone(),
                )
                .await?;
                tokio::spawn(service);

                eyre::Ok((
                    chain.id(),
                    Chain {
                        provider,
                        transactions: handle,
                        chain: *chain,
                        native_symbol: desc.native_symbol.clone(),
                        assets: desc.assets.clone(),
                        sim_mode: desc.sim_mode,
                        fees: desc.fees.clone(),
                        signers: chain_signers,
                        settler_address: desc.settler_address,
                    },
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

        if let Some(rebalance_config) = &config.rebalance_service {
            let funder_owner = DynSigner::from_raw(&rebalance_config.funder_owner_key).await?;

            let mut bridges: Vec<Box<dyn Bridge>> = Vec::new();

            if let Some(binance) = &rebalance_config.binance {
                bridges.push(Box::new(
                    BinanceBridge::new(
                        providers_with_chain.clone(),
                        tx_handles.clone(),
                        binance.clone(),
                        chains
                            .iter()
                            .flat_map(|(chain_id, chain)| {
                                chain
                                    .assets
                                    .interop_iter()
                                    .map(|(_, desc)| ((*chain_id, desc.address), desc.clone()))
                            })
                            .collect(),
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

            let service = RebalanceService::new(
                chains
                    .iter()
                    .flat_map(|(chain_id, chain)| {
                        chain
                            .assets
                            .interop_iter()
                            .map(|(asset_uid, desc)| (*chain_id, (asset_uid.clone(), desc.clone())))
                    })
                    .collect(),
                liquidity_tracker.clone(),
                bridges,
                rebalance_config.thresholds.clone(),
            );
            tokio::spawn(service.into_future().await?);
        }

        // Create and spawn the interop service if configured
        let interop = if let Some(interop_config) = &config.interop {
            let (interop_service, interop_handle) =
                InteropService::new(tx_handles, liquidity_tracker.clone(), interop_config.clone())
                    .await?;

            tokio::spawn(interop_service);
            Some(interop_handle)
        } else {
            None
        };

        Ok(Self { chains, interop })
    }

    /// Get the number of chains.
    pub fn len(&self) -> usize {
        self.chains.len()
    }

    /// Check whether there are any chains or not.
    pub fn is_empty(&self) -> bool {
        self.chains.is_empty()
    }

    /// Get the [`Chain`] object for a given chain ID.
    pub fn get(&self, chain_id: ChainId) -> Option<Chain> {
        self.chains.get(&chain_id).cloned()
    }

    /// Get the [`Chain`] object for a given chain ID.
    ///
    /// Returns a [`RelayError::UnsupportedChain`] if no chain with the id is found.
    pub fn ensure_chain(&self, chain_id: ChainId) -> Result<Chain, RelayError> {
        self.get(chain_id).ok_or(RelayError::UnsupportedChain(chain_id))
    }

    /// Returns an iterator over all installed [`Chain`]s.
    pub fn chains_iter(&self) -> impl Iterator<Item = &Chain> {
        self.chains.values()
    }

    /// Get an iterator over the supported chain IDs.
    pub fn chain_ids_iter(&self) -> impl Iterator<Item = &ChainId> {
        self.chains.keys()
    }

    /// Returns the total amount of signers across all configured chains.
    pub fn total_signers(&self) -> usize {
        self.chains_iter().map(|c| c.signers_count()).sum()
    }

    /// Get the [`AssetDescriptor`] for an asset on a chain, if it exists.
    pub fn asset(
        &self,
        chain_id: ChainId,
        address: Address,
    ) -> Option<(&AssetUid, &AssetDescriptor)> {
        self.chains.get(&chain_id).and_then(|chain| chain.assets.find_by_address(address))
    }

    /// Get the [`AssetDescriptor`] for a fee token on a chain, if it exists.
    pub fn fee_token(
        &self,
        chain_id: ChainId,
        fee_token: Address,
    ) -> Option<(&AssetUid, &AssetDescriptor)> {
        self.asset(chain_id, fee_token).filter(|(_, desc)| desc.fee_token)
    }

    /// Get the fee tokens for a chain.
    pub fn fee_tokens(&self, chain_id: ChainId) -> Option<Vec<(AssetUid, AssetDescriptor)>> {
        self.get(chain_id).map(|chain| chain.assets.fee_tokens())
    }

    /// Get the [`AssetDescriptor`] for a relayable token on a chain, if it exists.
    pub fn interop_asset(
        &self,
        chain_id: ChainId,
        asset: Address,
    ) -> Option<(&AssetUid, &AssetDescriptor)> {
        self.asset(chain_id, asset).filter(|(_, desc)| desc.interop)
    }

    /// Get the tokens relayable across chains.
    pub fn interop_tokens(&self, chain_id: ChainId) -> Option<Vec<(AssetUid, AssetDescriptor)>> {
        self.get(chain_id).map(|chain| chain.assets.interop_tokens())
    }

    /// Get the native token for a chain, if defined.
    pub fn native_token(&self, chain_id: ChainId) -> Option<(&AssetUid, &AssetDescriptor)> {
        self.chains.get(&chain_id).and_then(|chain| chain.assets.native())
    }

    /// Maps an asset on `src_chain_id` to an equivalent asset on `dst_chain_id`.
    ///
    /// Returns `None` if there is no equivalent asset, or if the equivalent asset is not enabled
    /// for interop.
    pub fn map_interop_asset(
        &self,
        src_chain_id: ChainId,
        dst_chain_id: ChainId,
        asset: Address,
    ) -> Option<&AssetDescriptor> {
        let (asset_uid, _) = self.interop_asset(src_chain_id, asset)?;
        self.chains
            .get(&dst_chain_id)
            .and_then(|dst_chain| dst_chain.assets.get(asset_uid).filter(|desc| desc.interop))
    }

    /// Maps an asset on `chain_id` to equivalent assets on other chains.
    ///
    /// Returns an empty iterator if there are no equivalent assets, or if the equivalent assets are
    /// not enabled for interop.
    pub fn map_interop_assets_per_chain(
        &self,
        chain_id: ChainId,
        asset: Address,
    ) -> impl Iterator<Item = (ChainId, &AssetDescriptor)> {
        let asset_uid = self.interop_asset(chain_id, asset).map(|(uid, _)| uid);

        self.chains_iter().filter_map(move |chain| {
            let asset_uid = asset_uid.as_ref()?;
            chain.assets().get(asset_uid).filter(|desc| desc.interop).map(|desc| (chain.id(), desc))
        })
    }

    /// Get the interop service handle.
    pub fn interop(&self) -> Option<&InteropServiceHandle> {
        self.interop.as_ref()
    }

    /// Get the settler address for a chain.
    ///
    /// Returns an error if the chain is not supported or if the chain has no settler address
    /// configured.
    pub fn settler_address(&self, chain_id: ChainId) -> Result<Address, SettlementError> {
        let chain_obj = self.get(chain_id).ok_or(SettlementError::UnsupportedChain(chain_id))?;

        chain_obj.settler_address().ok_or_else(|| SettlementError::MissingSettlerAddress(chain_id))
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

async fn try_build_provider(
    chain_id: ChainId,
    endpoint: &Url,
    sequencer_endpoint: Option<&Url>,
) -> eyre::Result<DynProvider> {
    let (transport, is_local) = create_transport(endpoint).await?;

    let builder =
        ClientBuilder::default().layer(TraceLayer::new(chain_id)).layer(RETRY_LAYER.clone());

    let client = if let Some(sequencer_url) = sequencer_endpoint {
        let sequencer =
            BuiltInConnectionString::from_str(sequencer_url.as_str())?.connect_boxed().await?;

        info!("Configured sequencer forwarding for chain {chain_id}");

        builder.layer(SequencerLayer::new(sequencer)).transport(transport, is_local)
    } else {
        builder.transport(transport, is_local)
    };

    eyre::Ok(
        ProviderBuilder::new()
            .connect_client(client.with_poll_interval(DEFAULT_POLL_INTERVAL))
            .erased(),
    )
}
