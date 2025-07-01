use crate::{
    liquidity::{
        LiquidityTracker,
        bridge::{Bridge, BridgeEvent, Transfer, TransferId, TransferState},
    },
    storage::{RelayStorage, StorageApi},
    types::{CoinKind, FeeTokens},
};
use alloy::primitives::{Address, ChainId, I256, U256, map::HashMap, uint};
use futures_util::{
    StreamExt,
    future::TryJoinAll,
    stream::{SelectAll, select_all},
};
use std::{ops::RangeInclusive, time::Duration};
use tracing::warn;

#[derive(Debug, Clone, Copy)]
pub struct Asset {
    address: Address,
    chain_id: ChainId,
    kind: CoinKind,
}

/// A service that rebalances liquidity across chains.
#[derive(Debug)]
pub struct RebalanceService {
    assets: Vec<Asset>,
    storage: RelayStorage,
    tracker: LiquidityTracker,
    bridges: SelectAll<Box<dyn Bridge>>,
    transfers_in_progress: Vec<Transfer>,
}

impl RebalanceService {
    /// Creates a new [`RebalanceService`].
    pub fn new(
        tokens: &FeeTokens,
        tracker: LiquidityTracker,
        bridges: impl IntoIterator<Item = Box<dyn Bridge>>,
    ) -> Self {
        let assets = tokens
            .iter()
            .flat_map(|(chain, tokens)| {
                tokens.iter().filter(|t| t.interop).map(|t| Asset {
                    address: t.address,
                    chain_id: *chain,
                    kind: t.kind,
                })
            })
            .collect();
        Self {
            assets,
            storage: tracker.storage().clone(),
            tracker,
            bridges: select_all(bridges),
            transfers_in_progress: Default::default(),
        }
    }
}

impl RebalanceService {
    /// Returns minimum balance that we need to hold for the given asset.
    fn get_threshold(&self, asset: &Asset) -> U256 {
        match asset.kind {
            CoinKind::ETH => uint!(100_000_000_000_000_000_U256),
            CoinKind::USDC | CoinKind::USDT => uint!(1_000_000_000_U256),
        }
    }

    /// Returns minimum amount for rebalancing to be performed.
    fn get_min_rebalance(&self, asset: &Asset) -> U256 {
        self.get_threshold(asset) / uint!(10_U256)
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
                    .iter()
                    .filter(|t| t.to.1 == asset.address && t.to.0 == asset.chain_id)
                    .map(|t| t.amount)
                    .sum::<U256>();

                let range = (*range.start())..=(range.end() + pending_inbound);

                eyre::Ok((*asset, range))
            })
            .collect::<TryJoinAll<_>>()
            .await?;

        Ok(balances)
    }

    /// Initiates a cross-chain transfer through a bridge.
    async fn bridge(&mut self, from: Asset, to: Asset, amount: U256) -> eyre::Result<()> {
        // Find bridge that supports the given asset.
        let Some(bridge) = self.bridges.iter_mut().find(|bridge| {
            bridge.supports((from.chain_id, from.address), (to.chain_id, to.address))
        }) else {
            eyre::bail!("no bridge for the given asset");
        };

        let transfer = Transfer {
            id: TransferId::random(),
            bridge_id: bridge.id().into(),
            from: (from.chain_id, from.address),
            to: (to.chain_id, to.address),
            amount,
        };

        // Lock liquidity and save transfer in database.
        self.tracker.try_lock_liquidity_for_bridge(&transfer).await?;

        // Send the transfer.
        tokio::spawn(bridge.process(transfer.clone()));

        self.transfers_in_progress.push(transfer);

        Ok(())
    }

    /// Finds next rebalance that needs to be delegated to a bridge.
    async fn find_next_rebalance(&self) -> eyre::Result<Option<(Asset, Asset, U256)>> {
        let mut coin_kind_to_deltas: HashMap<_, Vec<_>> = HashMap::default();

        for (asset, balance) in self.balance_ranges().await? {
            let threshold = self.get_threshold(&asset);

            let min_delta = I256::from(*balance.start()) - I256::from(threshold);
            let max_delta = I256::from(*balance.end()) - I256::from(threshold);

            coin_kind_to_deltas.entry(asset.kind).or_default().push((asset, min_delta..=max_delta));
        }

        for deltas in coin_kind_to_deltas.values() {
            // Find if there's an upper bound that is negative which means that even in the best
            // case scenario we'll be below threshold.
            let Some(min_negative) =
                deltas.iter().filter(|(_, d)| d.end().is_negative()).min_by_key(|(_, d)| *d.end())
            else {
                continue;
            };

            // Find if there's a lower bound that is positive which means that even in the worst
            // case scenario we'll be above threshold.
            let Some(max_positive) = deltas
                .iter()
                .filter(|(_, d)| d.start().is_positive())
                .max_by_key(|(_, d)| *d.start())
            else {
                warn!(
                    "below threshold on chain {} but don't have funds to cover",
                    min_negative.0.chain_id
                );
                continue;
            };

            let rebalance_amount =
                U256::from((-(*min_negative.1.end())).min(*max_positive.1.start()));

            if rebalance_amount >= self.get_min_rebalance(&min_negative.0) {
                return Ok(Some((max_positive.0, min_negative.0, rebalance_amount)));
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
            self.transfers_in_progress.push(transfer);
        }

        let fut = async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                tokio::select! {
                    // Wake up to find next rebalance.
                    _ = interval.tick() => {
                        if let Ok(Some((from, to, amount))) = self.find_next_rebalance().await {
                            if let Err(err) = self.bridge(from, to, amount).await {
                                warn!("failed to bridge: {}", err);
                            }
                        }
                    }
                    // Handle bridge events.
                    Some(event) = self.bridges.next() => {
                        match event {
                            // Unlock liquidity for completed/failed transfers.
                            BridgeEvent::TransferState(transfer_id, state) => {
                                match state {
                                    // Once source transfer is completed (the one we've locked liquidity for),
                                    // we need to atomically update the state and unlock liquidity.
                                    TransferState::Sent(_) | TransferState::OutboundFailed => {
                                        let _ = self.storage.update_transfer_state_and_unlock_liquidity(transfer_id, state).await;
                                    }
                                    _ => {
                                        let _ = self.storage.update_transfer_state(transfer_id, state).await;
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
