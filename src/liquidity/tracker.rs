use crate::{
    error::StorageError,
    liquidity::bridge::Transfer,
    storage::{LockLiquidityInput, RelayStorage, StorageApi},
    types::IERC20,
};
use alloy::{
    primitives::{Address, BlockNumber, ChainId, U256, map::HashMap},
    providers::{DynProvider, MulticallError, Provider},
};
use futures_util::future::TryJoinAll;
use std::{ops::RangeInclusive, time::Duration};
use tracing::error;

/// An address on a specific chain.
pub type ChainAddress = (ChainId, Address);

/// Errors that may occur when locking liquidity.
#[derive(Debug, thiserror::Error)]
pub enum LiquidityTrackerError {
    /// Multicall error.
    #[error(transparent)]
    Multicall(#[from] MulticallError),

    /// Not enough liquidity for locking.
    #[error("not enough liqudiity")]
    NotEnoughLiquidity,

    /// Storage error.
    #[error(transparent)]
    Storage(#[from] StorageError),
}

/// Wrapper around [`LiquidityTrackerInner`] that is used to track liquidity.
#[derive(Debug, Clone)]
pub struct LiquidityTracker {
    funder_address: Address,
    providers: HashMap<ChainId, DynProvider>,
    storage: RelayStorage,
}

impl LiquidityTracker {
    /// Creates a new liquidity tracker.
    pub fn new(
        providers: HashMap<ChainId, DynProvider>,
        funder_address: Address,
        storage: RelayStorage,
    ) -> Self {
        let this = Self { providers: providers.clone(), funder_address, storage: storage.clone() };

        // Spawn a task that periodically cleans up the pending unlocks for older blocks.
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;

                let result = providers
                    .iter()
                    .map(async |(chain, provider)| {
                        let latest_block = provider.get_block_number().await?;
                        // Remove everything older than 10 blocks
                        storage
                            .prune_unlocked_entries(*chain, latest_block.saturating_sub(10))
                            .await?;
                        eyre::Ok(())
                    })
                    .collect::<TryJoinAll<_>>()
                    .await;

                if let Err(e) = result {
                    error!("liquidity tracker task failed: {:?}", e);
                }
            }
        });

        this
    }

    async fn get_balance_with_block(
        &self,
        chain_id: ChainId,
        asset: Address,
    ) -> Result<(U256, BlockNumber), MulticallError> {
        let provider = &self.providers[&chain_id];
        let (balance, block_number) = if !asset.is_zero() {
            let (balance, block_number) = provider
                .multicall()
                .add(IERC20::new(asset, provider).balanceOf(self.funder_address))
                .get_block_number()
                .aggregate()
                .await?;
            (balance, block_number.to::<u64>())
        } else {
            let block_number = provider.get_block_number().await?;
            let balance =
                provider.get_balance(self.funder_address).block_id(block_number.into()).await?;
            (balance, block_number)
        };

        Ok((balance, block_number))
    }

    /// Fetches the potential liquidity range for an asset.
    ///
    /// Range start is the minimum balance that we can have for the asset, accounting for all of the
    /// locked liquidity.
    ///
    /// Range end is the current on-chain balance for this asset, without accounting for any locks.
    pub async fn balance_range(
        &self,
        chain_id: ChainId,
        asset: Address,
    ) -> Result<RangeInclusive<U256>, LiquidityTrackerError> {
        let (max_balance, block_number) = self.get_balance_with_block(chain_id, asset).await?;
        let total_locked =
            self.storage.get_total_locked_at((chain_id, asset), block_number).await?;
        let min_balance = max_balance.saturating_sub(total_locked);
        Ok(min_balance..=max_balance)
    }

    async fn prepare_lock_inputs(
        &self,
        assets: impl IntoIterator<Item = (ChainId, Address, U256)>,
    ) -> Result<HashMap<ChainAddress, LockLiquidityInput>, LiquidityTrackerError> {
        // Deduplicate assets by chain and asset address
        let inputs: HashMap<_, U256> = assets
            .into_iter()
            .map(|(chain, asset, amount)| ((chain, asset), amount))
            .fold(HashMap::default(), |mut map, (k, v)| {
                *map.entry(k).or_default() += v;
                map
            });

        // Construct inputs for liquidity tracker by fetching balances
        let inputs = inputs
            .into_iter()
            .map(async |((chain, asset), amount)| {
                let (balance, block_number) = self.get_balance_with_block(chain, asset).await?;
                Ok::<_, MulticallError>((
                    (chain, asset),
                    LockLiquidityInput {
                        current_balance: balance,
                        block_number,
                        lock_amount: amount,
                    },
                ))
            })
            .collect::<TryJoinAll<_>>()
            .await?
            .into_iter()
            .collect();

        Ok(inputs)
    }

    /// Locks liquidity for an interop bundle.
    pub async fn try_lock_liquidity(
        &self,
        assets: impl IntoIterator<Item = (ChainId, Address, U256)>,
    ) -> Result<(), LiquidityTrackerError> {
        self.storage.try_lock_liquidity(self.prepare_lock_inputs(assets).await?).await?;

        Ok(())
    }

    /// Locks liquidity for an interop bundle.
    pub async fn try_lock_liquidity_for_bridge(
        &self,
        transfer: &Transfer,
    ) -> Result<(), LiquidityTrackerError> {
        let input = self
            .prepare_lock_inputs(core::iter::once((
                transfer.from.0,
                transfer.from.1,
                transfer.amount,
            )))
            .await?
            .remove(&transfer.from)
            .unwrap();

        self.storage.lock_liquidity_for_bridge(transfer, input).await?;

        Ok(())
    }

    /// Unlocks liquidity from an interop bundle.
    pub async fn unlock_liquidity(
        &self,
        asset: ChainAddress,
        amount: U256,
        at: BlockNumber,
    ) -> Result<(), LiquidityTrackerError> {
        self.storage.unlock_liquidity(asset, amount, at).await?;
        Ok(())
    }

    /// Returns reference to underlying [`RelayStorage`].
    pub fn storage(&self) -> &RelayStorage {
        &self.storage
    }
}
