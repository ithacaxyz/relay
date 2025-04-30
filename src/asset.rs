//! Asset info service.
use crate::{
    error::{AssetError, RelayError},
    types::{
        Asset, AssetDiff, AssetDiffs, AssetWithInfo,
        IERC20::{self, IERC20Events},
        IERC721::IERC721Events,
    },
};
use alloy::{
    network::TransactionBuilder,
    primitives::{
        Address, ChainId, U256,
        aliases::I512,
        map::{HashMap, HashSet},
    },
    providers::Provider,
    rpc::types::{
        Log, TransactionRequest,
        simulate::{SimBlock, SimulatePayload},
    },
    sol_types::{SolCall, SolEventInterface},
};
use schnellru::{ByLength, LruMap};
use std::{
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::sync::{
    mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
    oneshot,
};
use tracing::{error, trace};

/// Messages accepted by the [`AssetInfoService`].
#[derive(Debug)]
pub enum AssetInfoServiceMessage {
    /// Message to lookup asset infos for a chain.
    Lookup {
        /// Chain id.
        chain_id: u64,
        /// Requested assets.
        assets: Vec<Asset>,
        /// Response channel.
        tx: oneshot::Sender<Vec<(Asset, Option<AssetWithInfo>)>>,
    },
    /// Message to update the cache with other assets.
    Update {
        /// Chain id.
        chain_id: u64,
        /// Asset infos to be pushed to cache.
        assets: Vec<AssetWithInfo>,
    },
}

/// Handle to communicate with the [`AssetInfoService`].
#[derive(Debug, Clone)]
pub struct AssetInfoServiceHandle {
    command_tx: UnboundedSender<AssetInfoServiceMessage>,
}

impl AssetInfoServiceHandle {
    /// Lookup asset info for a given chain and a list of assets. It first checks the cache, and if
    /// it cannot find it will query it from chain.
    ///
    /// # Note:
    /// Ensures that the returned map contains all the requested assets.
    pub async fn get_asset_info_list<P: Provider>(
        &self,
        provider: &P,
        assets: Vec<Asset>,
    ) -> Result<HashMap<Asset, AssetWithInfo>, RelayError> {
        // Get asset infos from cache
        let (req_tx, req_rx) = oneshot::channel();
        let chain_id = provider.get_chain_id().await?;
        let _ =
            self.command_tx.send(AssetInfoServiceMessage::Lookup { chain_id, assets, tx: req_tx });

        let cached_assets = req_rx.await.map_err(|_| AssetError::ServiceUnavailable)?;

        // If missing any asset info, then query it from chain
        let missing_assets: Vec<Address> = cached_assets
            .iter()
            .filter(|(_, info)| info.is_none())
            .map(|(asset, _)| asset.address())
            .collect();

        if missing_assets.is_empty() {
            // No missing asset info
            return Ok(cached_assets
                .into_iter()
                .flat_map(|(_, info)| info)
                .map(|info| (info.asset, info))
                .collect());
        }

        let missing_assets = get_info(provider, missing_assets).await?;

        // Push missing assets to cache
        let _ = self
            .command_tx
            .send(AssetInfoServiceMessage::Update { chain_id, assets: missing_assets.clone() });

        Ok(cached_assets
            .into_iter()
            .filter_map(|(_, info)| info)
            .chain(missing_assets)
            .map(|info| (info.asset, info))
            .collect())
    }

    /// Calculates the net asset difference for each account and asset based on logs.
    ///
    /// ERC20: We first accumulate for each EOA and asset a tuple of credits and debits, only
    /// calculating its final result at the end.
    ///
    /// ERC721: a positive [`AssetDiff`] value represents an inflow of the token ID. A negative
    /// value represents an outflow.
    pub async fn calculate_asset_diff<P: Provider>(
        &self,
        logs: impl Iterator<Item = Log>,
        provider: &P,
    ) -> Result<AssetDiffs, RelayError> {
        let mut seen_assets: HashSet<Asset> = HashSet::default();
        let mut fungible_diffs: HashMap<Address, HashMap<Asset, (U256, U256)>> = HashMap::default();
        let mut non_fungible_diffs: HashSet<(Address, Asset, I512)> = HashSet::default();
        let mut asset_diffs: HashMap<Address, Vec<AssetDiff>> = HashMap::default();

        for log in logs {
            // ERC-20
            if let Some((asset, transfer)) =
                IERC20Events::decode_log(&log.inner).ok().map(|ev| match ev.data {
                    IERC20Events::Transfer(t) => (Asset::from(log.inner.address), t),
                })
            {
                seen_assets.insert(asset);

                // credits
                fungible_diffs
                    .entry(transfer.to)
                    .or_default()
                    .entry(asset)
                    .and_modify(|(c, _)| *c += transfer.amount)
                    .or_insert((transfer.amount, U256::ZERO));
                // debits
                fungible_diffs
                    .entry(transfer.from)
                    .or_default()
                    .entry(asset)
                    .and_modify(|(_, d)| *d += transfer.amount)
                    .or_insert((U256::ZERO, transfer.amount));
            }
            // ERC-721
            else if let Some((asset, transfer)) =
                IERC721Events::decode_log(&log.inner).ok().map(|ev| match ev.data {
                    IERC721Events::Transfer(t) => (Asset::from(log.inner.address), t),
                })
            {
                seen_assets.insert(asset);

                let id = I512::try_from_le_slice(transfer.id.as_le_slice())
                    .expect("should convert from u256");

                for &(eoa, change) in &[(transfer.from, -id), (transfer.to, id)] {
                    // if there's an opposite change for the given id, remove it. eg [-id,+id]
                    if !non_fungible_diffs.remove(&(eoa, asset, -change)) {
                        // no opposite found, so insert it
                        non_fungible_diffs.insert((eoa, asset, change));
                    }
                }
            }
        }

        // fetch assets metadata
        let metadata =
            self.get_asset_info_list(provider, seen_assets.into_iter().collect()).await?;

        // calculate fungible diffs from credit & debit entries
        for (owner, asset_map) in fungible_diffs {
            for (asset, (credit, debit)) in asset_map {
                let net = I512::try_from_le_slice(credit.as_le_slice())
                    .expect("should convert from u256")
                    - I512::try_from_le_slice(debit.as_le_slice())
                        .expect("should convert from u256");
                if net.is_zero() {
                    continue;
                }
                let info = &metadata[&asset];
                asset_diffs.entry(owner).or_default().push(AssetDiff {
                    address: (!asset.is_native()).then(|| asset.address()),
                    name: info.name.clone(),
                    symbol: info.symbol.clone(),
                    decimals: info.decimals,
                    value: net,
                });
            }
        }

        // push non fungible entries
        for (owner, asset, id) in non_fungible_diffs {
            let info = &metadata[&asset];
            asset_diffs.entry(owner).or_default().push(AssetDiff {
                address: Some(asset.address()),
                name: info.name.clone(),
                symbol: info.symbol.clone(),
                decimals: info.decimals,
                value: id,
            });
        }

        Ok(AssetDiffs(asset_diffs.into_iter().collect()))
    }
}
/// Service that provides [`AssetWithInfo`] about any kind of asset.
///
/// TODO: apart from onchain, there should be a more trusted source that can be passed when
/// initializing it.
#[derive(Debug)]
pub struct AssetInfoService {
    /// Cached asset metadata per chain.
    cache: LruMap<(ChainId, Asset), AssetWithInfo>,
    /// Sender half for asset info messages.
    command_tx: UnboundedSender<AssetInfoServiceMessage>,
    /// Incoming messages for the service.
    command_rx: UnboundedReceiver<AssetInfoServiceMessage>,
}

impl AssetInfoService {
    /// Creates a new [`AssetInfoService`].
    pub fn new(capacity: u32) -> Self {
        let (command_tx, command_rx) = unbounded_channel();
        Self { cache: LruMap::new(ByLength::new(capacity)), command_tx, command_rx }
    }

    /// Returns a new handle connected to this service.
    pub fn handle(&self) -> AssetInfoServiceHandle {
        AssetInfoServiceHandle { command_tx: self.command_tx.clone() }
    }

    /// Lookups the asset info for a chain id and a list of assets.
    pub fn lookup(
        &mut self,
        chain_id: ChainId,
        assets: Vec<Asset>,
        response_tx: oneshot::Sender<Vec<(Asset, Option<AssetWithInfo>)>>,
    ) {
        trace!(chain_id, ?assets, "Received lookup request for asset infos.");

        let _ = response_tx.send(
            assets
                .into_iter()
                .map(|asset| {
                    let info = if asset.is_native() {
                        // todo: only supports eth as native coin for now
                        Some(AssetWithInfo {
                            asset: Asset::Native,
                            symbol: Some("ETH".to_string()),
                            decimals: Some(18u8),
                            name: None,
                        })
                    } else {
                        self.cache.get(&(chain_id, asset)).cloned()
                    };

                    (asset, info)
                })
                .collect(),
        );
    }

    /// Updates the cache with missing asset infos.
    pub fn update(&mut self, chain_id: ChainId, assets: Vec<AssetWithInfo>) {
        trace!(chain_id, ?assets, "Received update request for asset infos.");

        for asset_with_info in assets {
            self.cache.get_or_insert((chain_id, asset_with_info.asset), || asset_with_info);
        }
    }
}

impl Future for AssetInfoService {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        while let Some(action) = ready!(this.command_rx.poll_recv(cx)) {
            match action {
                AssetInfoServiceMessage::Lookup { chain_id, assets, tx } => {
                    this.lookup(chain_id, assets, tx);
                }
                AssetInfoServiceMessage::Update { chain_id, assets } => {
                    this.update(chain_id, assets);
                }
            }
        }

        Poll::Pending
    }
}

/// Gets metadata from many assets on chain.
async fn get_info<P: Provider>(
    provider: &P,
    assets: Vec<Address>,
) -> Result<Vec<AssetWithInfo>, RelayError> {
    let transactions = assets.iter().flat_map(|asset| {
        let to_asset = TransactionRequest::default().with_to(*asset);
        [
            to_asset.clone().with_input(IERC20::decimalsCall::SELECTOR),
            to_asset.clone().with_input(IERC20::symbolCall::SELECTOR),
            to_asset.with_input(IERC20::nameCall::SELECTOR),
        ]
    });

    let Some(call_bundle) = provider
        .simulate(
            &SimulatePayload::default().extend(SimBlock::default().extend_calls(transactions)),
        )
        .await?
        .pop()
    else {
        error!("Expected a bundle response, but found none.");
        return Err(AssetError::InvalidAssetInfoResponse.into());
    };

    // We should have 3 call responses per requested asset. (decimals, symbol, name)
    if call_bundle.calls.len() != 3 * assets.len() {
        error!(
            "Expected {} responses in bundle but found {}.",
            3 * assets.len(),
            call_bundle.calls.len()
        );
        return Err(AssetError::InvalidAssetInfoResponse.into());
    }

    let mut assets_with_info = Vec::with_capacity(assets.len());
    let mut call_bundle_iter = call_bundle.calls.into_iter();

    for asset in assets {
        let decimals = call_bundle_iter.next().expect("qed");
        let symbol = call_bundle_iter.next().expect("qed");
        let name = call_bundle_iter.next().expect("qed");

        // This can be a non-ERC20 asset or an out of standard one, so we can only attempt to query
        // & decode.
        assets_with_info.push(AssetWithInfo {
            asset: Asset::Token(asset),
            decimals: IERC20::decimalsCall::abi_decode_returns(&decimals.return_data).ok(),
            symbol: IERC20::symbolCall::abi_decode_returns(&symbol.return_data).ok(),
            name: IERC20::nameCall::abi_decode_returns(&name.return_data).ok(),
        })
    }

    Ok(assets_with_info)
}
