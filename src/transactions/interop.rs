use super::{
    RelayTransaction, TransactionFailureReason, TransactionServiceHandle, TransactionStatus,
};
use crate::{
    error::StorageError,
    types::{IERC20, rpc::BundleId},
};
use alloy::{
    primitives::{Address, BlockNumber, ChainId, U256, map::HashMap},
    providers::{DynProvider, MulticallError, Provider},
};
use futures_util::future::{JoinAll, TryJoinAll};
use std::{
    collections::BTreeMap,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::{Mutex, mpsc};
use tracing::{error, instrument};

/// Bundle of transactions for cross-chain execution.
#[derive(Debug, Clone)]
pub struct InteropBundle {
    /// Unique identifier for the bundle.
    pub id: BundleId,
    /// Source chain transactions.
    pub src_transactions: Vec<RelayTransaction>,
    /// Destination chain transactions. Those can't be sent until all source chain transactions
    /// are confirmed.
    pub dst_transactions: Vec<RelayTransaction>,
}

impl InteropBundle {
    /// Creates a new interop bundle.
    pub fn new(
        id: BundleId,
        src_transactions: Vec<RelayTransaction>,
        dst_transactions: Vec<RelayTransaction>,
    ) -> Self {
        Self { id, src_transactions, dst_transactions }
    }
}

/// Errors that can occur during interop bundle processing.
#[derive(Debug, thiserror::Error)]
enum InteropBundleError {
    /// Transaction failed.
    #[error("transaction failed: {0}")]
    TransactionError(Arc<dyn TransactionFailureReason>),
    /// Not enough liquidity.
    #[error("don't have enough liquidity for the bundle")]
    NotEnoughLiquidity,
    /// Storage error.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// An error occurred during ABI encoding/decoding.
    #[error(transparent)]
    AbiError(#[from] alloy::sol_types::Error),
    /// Multicall error.
    #[error(transparent)]
    MulticallError(#[from] MulticallError),
}

impl From<Arc<dyn TransactionFailureReason>> for InteropBundleError {
    fn from(err: Arc<dyn TransactionFailureReason>) -> Self {
        Self::TransactionError(err)
    }
}

#[derive(Debug)]
pub enum InteropServiceMessage {
    /// Send an [`InteropBundle`].
    SendBundle(InteropBundle),
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
    locked_liquidity: HashMap<(ChainId, Address), U256>,
    /// Liquidity amounts that are unlocked at certain block numbers.
    ///
    /// Those correspond to blocks when we've sent funds to users.
    pending_unlocks: HashMap<(ChainId, Address), BTreeMap<BlockNumber, U256>>,
}

impl LiquidityTrackerInner {
    /// Does a pessimistic estimate of our balance in the given asset, subtracting all of the locked
    /// balances and adding all of the unlocked ones.
    fn available_balance(&self, asset: (ChainId, Address), input: &LockLiquidityInput) -> U256 {
        let locked = self.locked_liquidity.get(&asset).copied().unwrap_or_default();
        let unlocked = self
            .pending_unlocks
            .get(&asset)
            .map(|unlocks| {
                unlocks.range(..=input.balance_at).map(|(_, amount)| *amount).sum::<U256>()
            })
            .unwrap_or_default();

        input.current_balance.saturating_add(unlocked).saturating_sub(locked)
    }

    /// Attempts to lock liquidity by firstly making sure that we have enough funds for it.
    async fn try_lock_liquidity(
        &mut self,
        assets: HashMap<(ChainId, Address), LockLiquidityInput>,
    ) -> Result<(), InteropBundleError> {
        // Make sure that we have enough funds for all transfers
        if assets
            .iter()
            .any(|(asset, input)| input.lock_amount > self.available_balance(*asset, input))
        {
            return Err(InteropBundleError::NotEnoughLiquidity);
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
        at: BlockNumber,
    ) {
        *self.pending_unlocks.entry((chain_id, asset)).or_default().entry(at).or_default() +=
            amount;
    }
}

/// Wrapper around [`LiquidityTrackerInner`] that is used to track liquidity.
#[derive(Debug, Default)]
struct LiquidityTracker {
    inner: Arc<Mutex<LiquidityTrackerInner>>,
    funder_address: Address,
    providers: HashMap<ChainId, DynProvider>,
}

impl LiquidityTracker {
    /// Creates a new liquidity tracker.
    pub fn new(providers: HashMap<ChainId, DynProvider>, funder_address: Address) -> Self {
        let inner = Arc::new(Mutex::new(Default::default()));
        let this = Self { inner: inner.clone(), providers: providers.clone(), funder_address };

        // Spawn a task that periodically cleans up the pending unlocks for older blocks.
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;

                let result = providers
                    .iter()
                    .map(async |(chain, provider)| {
                        let latest_block = provider.get_block_number().await?;
                        let mut lock = inner.lock().await;
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

    /// Locks liquidity for an interop bundle.
    pub async fn try_lock_liquidity(
        &self,
        assets: impl IntoIterator<Item = (ChainId, Address, U256)>,
    ) -> Result<(), InteropBundleError> {
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
                let provider = &self.providers[&chain];
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
                    let balance = provider
                        .get_balance(self.funder_address)
                        .block_id(block_number.into())
                        .await?;
                    (balance, block_number)
                };

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

        self.inner.lock().await.try_lock_liquidity(inputs).await?;

        Ok(())
    }

    /// Unlocks liquidity from an interop bundle.
    pub async fn unlock_liquidity(
        &self,
        chain_id: ChainId,
        asset: Address,
        amount: U256,
        at: BlockNumber,
    ) {
        self.inner.lock().await.unlock_liquidity(chain_id, asset, amount, at);
    }
}

/// Handle to communicate with the [`InteropService`].
#[derive(Debug, Clone)]
pub struct InteropServiceHandle {
    command_tx: mpsc::UnboundedSender<InteropServiceMessage>,
}

impl InteropServiceHandle {
    /// Sends an interop bundle to the service.
    pub fn send_bundle(
        &self,
        bundle: InteropBundle,
    ) -> Result<(), mpsc::error::SendError<InteropServiceMessage>> {
        self.command_tx.send(InteropServiceMessage::SendBundle(bundle))
    }
}

/// Internal state of the interop service.
#[derive(Debug)]
struct InteropServiceInner {
    tx_service_handles: HashMap<ChainId, TransactionServiceHandle>,
    liquidity_tracker: LiquidityTracker,
}

impl InteropServiceInner {
    /// Creates a new interop service inner state.
    fn new(
        tx_service_handles: HashMap<ChainId, TransactionServiceHandle>,
        liquidity_tracker: LiquidityTracker,
    ) -> Self {
        Self { tx_service_handles, liquidity_tracker }
    }

    async fn send_and_watch_transactions(
        &self,
        transactions: &[RelayTransaction],
    ) -> Result<Vec<u64>, InteropBundleError> {
        let mut handles = Vec::new();

        for tx in transactions {
            let handle = self
                .tx_service_handles
                .get(&tx.chain_id())
                .ok_or_else(|| {
                    let err =
                        Arc::new(format!("no transaction service for chain {}", tx.chain_id()));
                    InteropBundleError::TransactionError(err)
                })?
                .send_transaction(tx.clone())
                .await?;
            handles.push(handle);
        }

        // Wait for all transactions to confirm or fail
        let results = handles
            .into_iter()
            .map(|mut handle| async move {
                while let Some(status) = handle.recv().await {
                    match status {
                        TransactionStatus::Confirmed(receipt) => {
                            return Ok(receipt.block_number.unwrap_or_default());
                        }
                        TransactionStatus::Failed(err) => return Err(err),
                        _ => continue,
                    }
                }

                Err(Arc::new("transaction stream ended".to_string()))
            })
            .collect::<JoinAll<_>>()
            .await;

        // Collect results and return first error if any
        Ok(results.into_iter().collect::<Result<Vec<_>, _>>()?)
    }

    #[instrument(skip(self, bundle), fields(bundle_id = %bundle.id))]
    async fn send_and_watch_bundle(&self, bundle: InteropBundle) -> Result<(), InteropBundleError> {
        let asset_transfers = bundle
            .dst_transactions
            .iter()
            .map(|tx| {
                tx.quote.output.fund_transfers().map(|transfers| {
                    transfers.into_iter().map(|(asset, amount)| (tx.quote.chain_id, asset, amount))
                })
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        self.liquidity_tracker.try_lock_liquidity(asset_transfers.clone()).await?;

        self.send_and_watch_transactions(&bundle.src_transactions).await?;
        let dst_block_numbers = self.send_and_watch_transactions(&bundle.dst_transactions).await?;

        for ((chain_id, asset, amount), block_number) in
            asset_transfers.into_iter().zip(dst_block_numbers)
        {
            self.liquidity_tracker.unlock_liquidity(chain_id, asset, amount, block_number).await;
        }

        Ok(())
    }
}

/// Service for handling cross-chain interop bundles.
#[derive(Debug)]
pub struct InteropService {
    inner: Arc<InteropServiceInner>,
    command_rx: mpsc::UnboundedReceiver<InteropServiceMessage>,
}

impl InteropService {
    /// Creates a new interop service.
    pub async fn new(
        providers: HashMap<ChainId, DynProvider>,
        tx_service_handles: HashMap<ChainId, TransactionServiceHandle>,
        funder_address: Address,
    ) -> eyre::Result<(Self, InteropServiceHandle)> {
        let (command_tx, command_rx) = mpsc::unbounded_channel();

        let liquidity_tracker = LiquidityTracker::new(providers, funder_address);

        let service = Self {
            inner: Arc::new(InteropServiceInner::new(tx_service_handles, liquidity_tracker)),
            command_rx,
        };

        let handle = InteropServiceHandle { command_tx };

        Ok((service, handle))
    }
}

impl Future for InteropService {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        while let Poll::Ready(Some(command)) = self.command_rx.poll_recv(cx) {
            match command {
                InteropServiceMessage::SendBundle(bundle) => {
                    let inner = Arc::clone(&self.inner);
                    tokio::spawn(async move {
                        if let Err(e) = inner.send_and_watch_bundle(bundle).await {
                            error!("Failed to process interop bundle: {:?}", e);
                        }
                    });
                }
            }
        }

        Poll::Pending
    }
}
