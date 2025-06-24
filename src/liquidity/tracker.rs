use crate::types::IERC20;
use alloy::{
    primitives::{Address, BlockNumber, ChainId, U256, map::HashMap},
    providers::{DynProvider, MulticallError, Provider},
};
use futures_util::future::TryJoinAll;
use std::{collections::BTreeMap, ops::RangeInclusive, sync::Arc, time::Duration};
use tokio::sync::RwLock;
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
}

/// Input for [`LiquidityTrackerInner::try_lock_liquidity`].
#[derive(Debug)]
struct LockLiquidityInput {
    /// Current balance of the asset fetched from provider.
    current_balance: U256,
    /// Block number at which the balance was fetched.
    balance_at: BlockNumber,
    /// Amount of the asset we are trying to lock.
    lock_amount: U256,
}

/// Tracks liquidity of relay for interop bundles.
#[derive(Debug, Default)]
struct LiquidityTrackerInner {
    /// Assets that are about to be pulled from us, indexed by chain and asset address.
    ///
    /// Those correspond to pending cross-chain intents that are not yet confirmed.
    locked_liquidity: HashMap<ChainAddress, U256>,
    /// Liquidity amounts that are unlocked at certain block numbers.
    ///
    /// Those correspond to blocks when we've sent funds to users.
    pending_unlocks: HashMap<ChainAddress, BTreeMap<BlockNumber, U256>>,
}

impl LiquidityTrackerInner {
    /// Does a pessimistic estimate of our balance in the given asset, subtracting all of the locked
    /// balances and adding all of the unlocked ones.
    fn available_balance(
        &self,
        asset: ChainAddress,
        current_balance: U256,
        at: BlockNumber,
    ) -> U256 {
        let locked = self.locked_liquidity.get(&asset).copied().unwrap_or_default();
        let unlocked = self
            .pending_unlocks
            .get(&asset)
            .map(|unlocks| unlocks.range(..=at).map(|(_, amount)| *amount).sum::<U256>())
            .unwrap_or_default();

        current_balance.saturating_add(unlocked).saturating_sub(locked)
    }

    /// Attempts to lock liquidity by firstly making sure that we have enough funds for it.
    async fn try_lock_liquidity(
        &mut self,
        assets: HashMap<ChainAddress, LockLiquidityInput>,
    ) -> Result<(), LiquidityTrackerError> {
        // Make sure that we have enough funds for all transfers
        if assets.iter().any(|(asset, input)| {
            input.lock_amount
                > self.available_balance(*asset, input.current_balance, input.balance_at)
        }) {
            return Err(LiquidityTrackerError::NotEnoughLiquidity);
        }

        // Lock liquidity
        for (asset, input) in assets {
            *self.locked_liquidity.entry(asset).or_default() += input.lock_amount;
        }

        Ok(())
    }

    /// Unlocks liquidity by adding it to the pending unlocks mapping. This should be called once
    /// bundle is confirmed.
    fn unlock_liquidity(
        &mut self,
        chain_id: ChainId,
        asset: Address,
        amount: U256,
        at: Option<BlockNumber>,
    ) {
        if let Some(at) = at {
            *self.pending_unlocks.entry((chain_id, asset)).or_default().entry(at).or_default() +=
                amount;
        } else {
            self.locked_liquidity
                .entry((chain_id, asset))
                .and_modify(|locked| *locked = locked.saturating_sub(amount));
        }
    }
}

/// Wrapper around [`LiquidityTrackerInner`] that is used to track liquidity.
#[derive(Debug, Clone, Default)]
pub struct LiquidityTracker {
    inner: Arc<RwLock<LiquidityTrackerInner>>,
    funder_address: Address,
    providers: HashMap<ChainId, DynProvider>,
}

impl LiquidityTracker {
    /// Creates a new liquidity tracker.
    pub fn new(providers: HashMap<ChainId, DynProvider>, funder_address: Address) -> Self {
        let inner = Arc::new(RwLock::new(Default::default()));
        let this = Self { inner: inner.clone(), providers: providers.clone(), funder_address };

        // Spawn a task that periodically cleans up the pending unlocks for older blocks.
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;

                let result = providers
                    .iter()
                    .map(async |(chain, provider)| {
                        let latest_block = provider.get_block_number().await?;
                        let mut lock = inner.write().await;
                        let LiquidityTrackerInner { locked_liquidity, pending_unlocks } =
                            &mut *lock;
                        for (asset, unlocks) in pending_unlocks {
                            if asset.0 == *chain {
                                // Keep 10 blocks of pending unlocks
                                let to_keep = unlocks.split_off(&latest_block.saturating_sub(10));
                                let to_remove = core::mem::replace(unlocks, to_keep);

                                // Remove everything else from the locked mapping
                                for (_, unlock) in to_remove {
                                    locked_liquidity.entry(*asset).and_modify(|amount| {
                                        *amount = amount.saturating_sub(unlock);
                                    });
                                }
                            }
                        }
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
        let min_balance =
            self.inner.read().await.available_balance((chain_id, asset), max_balance, block_number);
        Ok(min_balance..=max_balance)
    }

    /// Locks liquidity for an interop bundle.
    pub async fn try_lock_liquidity(
        &self,
        assets: impl IntoIterator<Item = (ChainId, Address, U256)>,
    ) -> Result<(), LiquidityTrackerError> {
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
                        balance_at: block_number,
                        lock_amount: amount,
                    },
                ))
            })
            .collect::<TryJoinAll<_>>()
            .await?
            .into_iter()
            .collect();

        self.inner.write().await.try_lock_liquidity(inputs).await?;

        Ok(())
    }

    /// Unlocks liquidity from an interop bundle.
    pub async fn unlock_liquidity(
        &self,
        chain_id: ChainId,
        asset: Address,
        amount: U256,
        at: impl Into<Option<BlockNumber>>,
    ) {
        self.inner.write().await.unlock_liquidity(chain_id, asset, amount, at.into());
    }
}
