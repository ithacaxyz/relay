//! Assets
use crate::types::{
    Asset, AssetWithInfo,
    IERC20::{self},
};
use alloy::{
    network::TransactionBuilder,
    primitives::{Address, ChainId},
    providers::Provider,
    rpc::types::{Bundle, TransactionRequest},
    sol_types::SolCall,
};
use lru::LruCache;
use std::num::NonZeroUsize;
use tokio::sync::{
    mpsc::{UnboundedSender, unbounded_channel},
    oneshot,
};
use tracing::{trace, warn};

/// Service that returns metadata information for a requested chain id and asset.
#[derive(Debug)]
pub struct AssetInfoService {
    tx: UnboundedSender<AssetInfoMessage>,
}

/// Alias type for a lookup response.
type AssetLookupResponse = Option<Vec<(Asset, Option<AssetWithInfo>)>>;

/// Message type for the coin info service.
#[derive(Debug)]
pub enum AssetInfoMessage {
    /// Message to lookup the asset info for a chain id and a list of assets.
    Lookup {
        /// Chain id.
        chain_id: u64,
        /// Requested assets.
        assets: Vec<Asset>,
        /// Requested asset information
        tx: oneshot::Sender<AssetLookupResponse>,
    },
    /// Message to update the registry with other assets.
    Update {
        /// Chain id.
        chain_id: u64,
        /// Requested assets.
        assets: Vec<AssetWithInfo>,
    },
}

impl AssetInfoService {
    /// Creates a new asset info oracle given a list of providers and and maximum LRU capacity.
    ///
    /// A background task is spawned that handles lookup and updaterequests.
    pub fn new(supported_chains: Vec<ChainId>, capacity: NonZeroUsize) -> Self {
        let (tx, mut rx) = unbounded_channel();

        tokio::spawn(async move {
            let mut registry: LruCache<(ChainId, Asset), AssetWithInfo> = LruCache::new(capacity);

            for chain_id in &supported_chains {
                // todo: only supports eth as native coin for now
                registry.push(
                    (*chain_id, Asset::Native),
                    AssetWithInfo {
                        asset: Asset::Native,
                        symbol: Some("ETH".to_string()),
                        decimals: Some(18u8),
                        name: None,
                    },
                );
            }

            while let Some(message) = rx.recv().await {
                match message {
                    AssetInfoMessage::Lookup { chain_id, assets, tx } => {
                        trace!(chain_id, ?assets, "Received lookup request for coin information.");
                        if !supported_chains.contains(&chain_id) {
                            warn!(
                                chain_id,
                                ?assets,
                                "Received lookup request for an unknown chain_id"
                            );
                            let _ = tx.send(None);
                            continue;
                        };

                        let _ = tx.send(Some(
                            assets
                                .into_iter()
                                .map(|asset| (asset, registry.get(&(chain_id, asset)).cloned()))
                                .collect(),
                        ));
                    }
                    AssetInfoMessage::Update { chain_id, assets } => {
                        if !supported_chains.contains(&chain_id) {
                            warn!(
                                chain_id,
                                ?assets,
                                "Received update request for an unknown chain_id"
                            );
                            continue;
                        };

                        for asset_with_info in assets {
                            registry.get_or_insert((chain_id, asset_with_info.asset), || {
                                asset_with_info
                            });
                        }
                    }
                }
            }
        });

        Self { tx }
    }

    /// Lookup asset info for a given chain and a list of assets.
    pub async fn get_asset_info_list<P: Provider>(
        &self,
        provider: &P,
        chain_id: u64,
        assets: Vec<Asset>,
    ) -> eyre::Result<Vec<AssetWithInfo>> {
        let (req_tx, req_rx) = oneshot::channel();
        let _ = self.tx.send(AssetInfoMessage::Lookup { chain_id, assets, tx: req_tx });
        let cached_assets = req_rx.await.unwrap_or_default().unwrap_or_default();

        let missing_assets = get_info(
            provider,
            cached_assets
                .iter()
                .filter(|(asset, info)| info.is_none() && !asset.is_native())
                .map(|(asset, _)| asset.address()),
        )
        .await?;

        if !missing_assets.is_empty() {
            let _ =
                self.tx.send(AssetInfoMessage::Update { chain_id, assets: missing_assets.clone() });
        };

        Ok(cached_assets.into_iter().filter_map(|(_, info)| info).chain(missing_assets).collect())
    }
}

async fn get_info<P: Provider>(
    provider: &P,
    assets: impl Iterator<Item = Address> + Clone,
) -> eyre::Result<Vec<AssetWithInfo>> {
    let transactions: Vec<_> = assets
        .clone()
        .flat_map(|asset| {
            let to_asset = TransactionRequest::default().with_to(asset);
            [
                to_asset.clone().with_input(IERC20::decimalsCall::SELECTOR),
                to_asset.clone().with_input(IERC20::symbolCall::SELECTOR),
                to_asset.clone().with_input(IERC20::nameCall::SELECTOR),
            ]
        })
        .collect();

    let infos = provider
        .call_many(&[Bundle { transactions, block_override: None }])
        .await?
        .pop()
        .expect("should have the bundle response");

    let mut assets_with_info = Vec::with_capacity(infos.len());
    let mut infos_iter = infos.into_iter();

    for asset in assets {
        let Some(decimals) = infos_iter.next() else { todo!() };
        let Some(symbol) = infos_iter.next() else { todo!() };
        let Some(name) = infos_iter.next() else { todo!() };

        // This can be a non-ERC20 asset or an out of standard one, so we can only attempt to query
        // & decode.
        assets_with_info.push(AssetWithInfo {
            asset: Asset::Token(asset),
            decimals: decimals.value.and_then(|data| {
                IERC20::decimalsCall::abi_decode_returns(&data, false).ok().map(|r| r._0)
            }),
            symbol: symbol.value.and_then(|data| {
                IERC20::symbolCall::abi_decode_returns(&data, false).ok().map(|r| r._0)
            }),
            name: name.value.and_then(|data| {
                IERC20::nameCall::abi_decode_returns(&data, false).ok().map(|r| r._0)
            }),
        })
    }

    Ok(assets_with_info)
}
