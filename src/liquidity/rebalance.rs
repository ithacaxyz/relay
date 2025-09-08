use crate::{
    liquidity::{
        LiquidityTracker,
        bridge::{Bridge, BridgeEvent, BridgeTransfer, BridgeTransferId, BridgeTransferState},
    },
    storage::{RelayStorage, StorageApi},
    types::{AssetDescriptor, AssetUid},
};
use alloy::primitives::{Address, ChainId, I256, U256, map::HashMap, uint};
use core::fmt;
use futures_util::{
    StreamExt,
    future::TryJoinAll,
    stream::{SelectAll, select_all},
};
use rust_decimal::{Decimal, prelude::ToPrimitive};
use std::{ops::RangeInclusive, time::Duration};
use tracing::{info, warn};

/// Scale factor for the asset decimals.
const SCALE_FACTOR: U256 = uint!(1000000000000000000_U256);

/// Represents an asset in a chain tracked by [`RebalanceService`].
#[derive(Debug, Clone)]
pub struct Asset {
    /// The unique ID of the asset.
    uid: AssetUid,
    /// Address of the asset, [`Address::ZERO`] for native.
    address: Address,
    /// Chain ID of the asset.
    chain_id: ChainId,
    /// Asset decimals.
    decimals: u8,
    /// Rebalance threshold.
    rebalance_threshold: U256,
}

impl fmt::Display for Asset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { uid, address, chain_id, .. } = self;
        write!(f, "{uid} @ {chain_id} ({address})")
    }
}

/// An instruction to rebalance an asset from one chain to another.
#[derive(Debug, Clone)]
pub struct AssetsToRebalance {
    /// Asset to rebalance from.
    from: Asset,
    /// Asset to rebalance to.
    to: Asset,
    /// Amount to rebalance.
    amount: U256,
}

/// A service that rebalances liquidity across chains.
///
/// The way rebalance service operates is by firstly finding an asset that is below threshold on one
/// chain and above on another, and triggering a transfer between them.
///
/// Transfers are handled via configured [`Bridge`] implementations. First bridge supporting the
/// given route is used.
#[derive(Debug)]
pub struct RebalanceService {
    /// Assets that are tracked and supported by the service.
    assets: Vec<Asset>,
    /// Relay storage used by the service.
    storage: RelayStorage,
    /// Liquidity tracker.
    tracker: LiquidityTracker,
    /// Bridges that are supported by the service. Wrapped in [`SelectAll`] to allow for
    /// polling of events from all bridges.
    bridges: SelectAll<Box<dyn Bridge>>,
    /// Transfers that are in progress.
    transfers_in_progress: HashMap<BridgeTransferId, BridgeTransfer>,
    /// Rebalance thresholds.
    thresholds: HashMap<AssetUid, Decimal>,
}

impl RebalanceService {
    /// Creates a new [`RebalanceService`].
    pub fn new(
        tokens: Vec<(ChainId, AssetUid, AssetDescriptor)>,
        tracker: LiquidityTracker,
        bridges: impl IntoIterator<Item = Box<dyn Bridge>>,
        thresholds: HashMap<AssetUid, Decimal>,
    ) -> Self {
        let assets = tokens
            .into_iter()
            .map(|(chain_id, asset_uid, desc)| {
                let rebalance_threshold = if let Some(configured) = thresholds.get(&asset_uid) {
                    let scaled = configured * Decimal::from(10u128.pow(desc.decimals as u32));
                    U256::from(scaled.to_u128().unwrap())
                } else {
                    U256::from(10u128.pow(desc.decimals as u32))
                };
                Asset {
                    uid: asset_uid.clone(),
                    address: desc.address,
                    chain_id,
                    decimals: desc.decimals,
                    rebalance_threshold,
                }
            })
            .collect();
        Self {
            assets,
            storage: tracker.storage().clone(),
            tracker,
            bridges: select_all(bridges),
            transfers_in_progress: Default::default(),
            thresholds,
        }
    }
}

impl RebalanceService {
    /// Returns minimum amount for rebalancing to be performed.
    fn get_min_rebalance(&self, src: &Asset, dst: &Asset) -> U256 {
        let min_supported = self
            .bridges
            .iter()
            .filter_map(|bridge| {
                bridge
                    .supports((src.chain_id, src.address), (dst.chain_id, dst.address))
                    .map(|direction| direction.min_amount)
            })
            .min()
            .unwrap_or(U256::MAX);

        (src.rebalance_threshold / uint!(10_U256)).max(min_supported)
    }

    /// Gets balance ranges for all assets.
    ///
    /// The lower bound is the minimum possible balance for the asset, accounting for all pending
    /// liquidity locks.
    ///
    /// Upper bound is maximum possible balance for the asset, accounting for all pending
    /// liquidity locks and pending cross-chain transfers.
    ///
    /// Rebalance will only be performed from a chain with lower bound above threshold to a chain
    /// with upper bound below threshold.
    async fn balance_ranges(&self) -> eyre::Result<Vec<(Asset, RangeInclusive<U256>)>> {
        let balances = self
            .assets
            .iter()
            .map(async |asset| {
                let range = self.tracker.balance_range(asset.chain_id, asset.address).await?;
                let pending_inbound = self
                    .transfers_in_progress
                    .values()
                    .filter(|t| t.to.1 == asset.address && t.to.0 == asset.chain_id)
                    .map(|t| t.amount)
                    .sum::<U256>();

                let range = (*range.start())..=(range.end() + pending_inbound);

                eyre::Ok((asset.clone(), range))
            })
            .collect::<TryJoinAll<_>>()
            .await?;

        Ok(balances)
    }

    /// Initiates a cross-chain transfer through a [`Bridge`].
    async fn bridge(&mut self, rebalance: AssetsToRebalance) -> eyre::Result<()> {
        let AssetsToRebalance { from, to, amount } = rebalance;

        // Find bridge that supports the given asset.
        let Some(bridge) = self.bridges.iter_mut().find(|bridge| {
            let Some(direction) =
                bridge.supports((from.chain_id, from.address), (to.chain_id, to.address))
            else {
                return false;
            };

            amount >= direction.min_amount
        }) else {
            eyre::bail!("no bridge for the given asset")
        };

        let transfer = BridgeTransfer {
            id: BridgeTransferId::random(),
            bridge_id: bridge.id().into(),
            from: (from.chain_id, from.address),
            to: (to.chain_id, to.address),
            amount,
        };

        info!(transfer_id=?transfer.id, "bridging {amount} of {from} to {to} via {}", bridge.id());

        // Lock liquidity and save transfer in database.
        self.tracker.try_lock_liquidity_for_bridge(&transfer).await?;

        // Send the transfer.
        tokio::spawn(bridge.process(transfer.clone()));

        self.transfers_in_progress.insert(transfer.id, transfer);

        Ok(())
    }

    /// Finds next rebalance that needs to be delegated to a bridge.
    async fn find_next_rebalance(&self) -> eyre::Result<Option<AssetsToRebalance>> {
        let mut coin_kind_to_scaled_deltas: HashMap<_, Vec<_>> = HashMap::default();

        for (asset, balance) in self.balance_ranges().await? {
            let threshold = asset.rebalance_threshold;

            let min_delta = I256::from(*balance.start()) - I256::from(threshold);
            let max_delta = I256::from(*balance.end()) - I256::from(threshold);

            let min_delta_scaled = min_delta * I256::from(SCALE_FACTOR)
                / I256::from(U256::from(10u128.pow(asset.decimals as u32)));
            let max_delta_scaled = max_delta * I256::from(SCALE_FACTOR)
                / I256::from(U256::from(10u128.pow(asset.decimals as u32)));

            coin_kind_to_scaled_deltas
                .entry(asset.uid.clone())
                .or_default()
                .push((asset.clone(), min_delta_scaled..=max_delta_scaled));
        }

        for deltas in coin_kind_to_scaled_deltas.values() {
            // Find if there's an upper bound that is negative which means that even in the best
            // case scenario we'll be below threshold.
            let Some((dst, dst_deltas)) =
                deltas.iter().filter(|(_, d)| d.end().is_negative()).min_by_key(|(_, d)| *d.end())
            else {
                continue;
            };

            // Find if there's a lower bound that is positive which means that even in the worst
            // case scenario we'll be above threshold.
            let Some((src, src_deltas)) = deltas
                .iter()
                .filter(|(_, d)| d.start().is_positive())
                .max_by_key(|(_, d)| *d.start())
            else {
                warn!("below threshold on chain {} but don't have funds to cover", dst.chain_id);
                continue;
            };

            let rebalance_amount_scaled =
                U256::from((-(*dst_deltas.end())).min(*src_deltas.start()));

            let rebalance_amount = rebalance_amount_scaled
                * U256::from(10u128.pow(src.decimals as u32))
                / SCALE_FACTOR;

            if rebalance_amount >= self.get_min_rebalance(src, dst) {
                return Ok(Some(AssetsToRebalance {
                    from: src.clone(),
                    to: dst.clone(),
                    amount: rebalance_amount,
                }));
            }
        }

        Ok(None)
    }

    /// Runs the rebalance service.
    pub async fn into_future(mut self) -> eyre::Result<impl Future<Output = ()>> {
        // Recover pending transfers from storage
        for transfer in self.storage.load_pending_transfers().await? {
            // Find the bridge that handles this transfer
            let Some(bridge) =
                self.bridges.iter_mut().find(|bridge| bridge.id() == transfer.bridge_id.as_ref())
            else {
                return Err(eyre::eyre!(
                    "found pending transfer for unknown bridge {}",
                    transfer.bridge_id
                ));
            };

            // Delegate the transfer to the bridge
            tokio::spawn(bridge.process(transfer.clone()));
            self.transfers_in_progress.insert(transfer.id, transfer);
        }

        let fut = async move {
            info!(
                bridges=?self.bridges.iter().map(|b| b.id()).collect::<Vec<_>>(),
                assets=?self.assets,
                thresholds=?self.thresholds,
                "Launched rebalance service"
            );

            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                tokio::select! {
                    // Wake up to find next rebalance.
                    _ = interval.tick() => {
                        if let Ok(Some(rebalance)) = self.find_next_rebalance().await
                            && let Err(err) = self.bridge(rebalance).await {
                                warn!("failed to bridge: {}", err);
                            }
                    }
                    // Handle bridge events.
                    Some(event) = self.bridges.next() => {
                        match event {
                            // Unlock liquidity for completed/failed transfers.
                            BridgeEvent::TransferState(transfer_id, state) => {
                                match state {
                                    BridgeTransferState::Pending => {
                                        // Do nothing.
                                    }
                                    // Once source transfer (the one we've locked liquidity for) is completed or failed,
                                    // we need to atomically update the state and unlock liquidity.
                                    BridgeTransferState::Sent(block_number) => {
                                        let _ = self.storage.update_transfer_state_and_unlock_liquidity(transfer_id, state, block_number).await;
                                    }
                                    BridgeTransferState::OutboundFailed => {
                                        let _ = self.storage.update_transfer_state_and_unlock_liquidity(transfer_id, state, 0).await;
                                        self.transfers_in_progress.remove(&transfer_id);
                                    }
                                    BridgeTransferState::Completed(_) => {
                                        let _ = self.storage.update_transfer_state(transfer_id, state).await;
                                        self.transfers_in_progress.remove(&transfer_id);
                                    }
                                    BridgeTransferState::InboundFailed => {
                                        let _ = self.storage.update_transfer_state(transfer_id, state).await;
                                        self.transfers_in_progress.remove(&transfer_id);
                                    }
                                };
                            }
                        }
                    }
                }
            }
        };

        Ok(fut)
    }
}
