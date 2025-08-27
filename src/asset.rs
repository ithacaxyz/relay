//! Asset info service.
use crate::{
    config::RelayConfig,
    error::{AssetError, ContractErrors::ContractErrorsErrors, RelayError},
    types::{
        Asset, AssetDeficit, AssetDeficits, AssetDiffs, AssetMetadata, AssetType, AssetWithInfo,
        IERC20::{self, IERC20Events},
        IERC721::{self, IERC721Events},
    },
};
use alloy::{
    primitives::{
        Address, ChainId, Log, U256, address,
        map::{HashMap, HashSet},
    },
    providers::{
        MULTICALL3_ADDRESS, Provider,
        bindings::IMulticall3::{self, Call3, aggregate3Call},
    },
    rpc::types::{TransactionRequest, state::StateOverride, trace::geth::CallFrame},
    sol_types::{SolCall, SolEventInterface, SolInterface},
    transports::TransportErrorKind,
};
use schnellru::{ByLength, LruMap};
use std::{
    ops::Not,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::{
    sync::{
        mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
        oneshot,
    },
    try_join,
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

    /// Gets all available `tokenURI` from a list of nfts.
    ///
    /// Since tokenURI calls revert if the token is not owned, this requires the simulated
    /// transaction with state overrides, so the URI calls can be done before and after:
    ///  * Before, so we can query the URIs from burned tokens.
    ///  * After, so we can query the URIs from minted tokens.
    ///
    /// # Note:
    /// Ensures that the returned map contains all the requested nfts.
    pub async fn get_erc721_uris<P: Provider>(
        &self,
        provider: &P,
        tx_request: &TransactionRequest,
        state_overrides: StateOverride,
        nfts: Vec<(Address, U256)>,
    ) -> Result<HashMap<(Address, U256), Option<String>>, RelayError> {
        if nfts.is_empty() {
            return Ok(HashMap::default());
        }

        let nft_calls = nfts
            .iter()
            .map(|(asset, id)| Call3 {
                target: *asset,
                allowFailure: true,
                callData: IERC721::tokenURICall { id: *id }.abi_encode().into(),
            })
            .collect::<Vec<_>>();

        // Extract transaction details
        let target =
            tx_request.to.as_ref().and_then(|to| to.to()).copied().unwrap_or(Address::ZERO);
        let calldata = tx_request.input.input().cloned().unwrap_or_default();

        // Simulation requires tx.origin balance to be u256::max, so we need to set it alongside the
        // state override below.
        let from = tx_request.from.unwrap_or(Address::ZERO);

        // Build multicall with three sections:
        // 1. Pre-transaction tokenURI calls (for burned tokens)
        // 2. Main transaction (must succeed)
        // 3. Post-transaction tokenURI calls (for minted tokens)
        let multicall_tx = TransactionRequest::default().from(from).to(MULTICALL3_ADDRESS).input(
            aggregate3Call {
                calls: [
                    nft_calls.clone(),
                    vec![Call3 { target, allowFailure: false, callData: calldata }],
                    nft_calls,
                ]
                .concat(),
            }
            .abi_encode()
            .into(),
        );

        let results = aggregate3Call::abi_decode_returns(
            &provider.call(multicall_tx).overrides(state_overrides).await?,
        )?;

        // Verify we got the expected number of results:
        // - nfts.len() tokenURI calls before the transaction
        // - Intent simulation call
        // - nfts.len() tokenURI calls after the transaction
        let expected_results = nfts.len() * 2 + 1;
        if results.len() != expected_results {
            return Err(TransportErrorKind::custom_str(&format!(
                "Expected {} results in multicall but found {}",
                expected_results,
                results.len()
            ))
            .into());
        }

        let before_simulation = &results[..nfts.len()];
        let after_simulation = &results[nfts.len() + 1..];

        Ok(nfts
            .into_iter()
            .enumerate()
            .map(|(i, (asset, id))| {
                let uri = decode_token_uri(&before_simulation[i])
                    .or_else(|| decode_token_uri(&after_simulation[i]));
                ((asset, id), uri)
            })
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
        tx_request: &TransactionRequest,
        state_overrides: StateOverride,
        logs: impl Iterator<Item = Log>,
        provider: &P,
    ) -> Result<AssetDiffs, RelayError> {
        let mut builder = AssetDiffs::builder();
        for log in logs {
            // ERC-20
            if let Some((asset, transfer)) =
                IERC20Events::decode_log(&log).ok().map(|ev| match ev.data {
                    IERC20Events::Transfer(t) => (Asset::from(log.address), t),
                })
            {
                builder.record_erc20(asset, transfer);
            }
            // ERC-721
            else if let Some((asset, transfer)) =
                IERC721Events::decode_log(&log).ok().map(|ev| match ev.data {
                    IERC721Events::Transfer(t) => (Asset::from(log.address), t),
                })
            {
                builder.record_erc721(asset, transfer);
            }
        }

        // fetch assets metadata
        let (metadata, tokens_uris) = try_join!(
            self.get_asset_info_list(provider, builder.seen_assets().copied().collect()),
            self.get_erc721_uris(
                provider,
                tx_request,
                state_overrides,
                builder.seen_nfts().collect()
            )
        )?;

        Ok(builder.build(metadata, tokens_uris))
    }

    /// Calculates the asset deficit for each account and asset based on calls.
    ///
    /// Supports only ERC-20 tokens.
    pub async fn calculate_asset_deficit<P: Provider>(
        &self,
        calls: impl Iterator<Item = CallFrame>,
        provider: &P,
    ) -> Result<AssetDeficits, RelayError> {
        // TODO: use a builder similar to asset difs

        let mut deficits = HashMap::new();
        let mut assets = HashSet::new();
        for call in calls {
            let Some(to) = call.to else { continue };

            let (asset, from, amount) = if let Ok((from, amount)) =
                // First try to decode as `transferFrom`, as it's
                // more likely the user is interacting with a
                // contract that tries to pull funds from their
                // wallet
                IERC20::transferFromCall::abi_decode(&call.input)
                        .map(|transfer| (transfer.from, transfer.amount))
                        .or_else(|_| {
                            // Then try to decode as `transfer` in case the user is making a direct
                            // transfer
                            IERC20::transferCall::abi_decode(&call.input)
                                .map(|transfer| (call.from, transfer.amount))
                        }) {
                (Asset::Token(to), from, amount)
            } else {
                // If both attempts failed, it's not an ERC-20 transfer. We're sure that it's not a
                // native token transfer either, because tracing of calls with insufficient native
                // token balance fails with an error.
                continue;
            };

            // Check if the call is reverted / errored due to insufficient balance. We check through
            // several common ERC-20 implementations, including specialized cases such as USDT.
            if let Some(revert_reason) = call.revert_reason
                && (
                    // OpenZeppelin < 5.0.0
                    revert_reason.contains("transfer amount exceeds balance") ||
                    // Solmate and other implementations that don't use SafeMath
                    revert_reason.contains("arithmetic underflow or overflow")
                )
            {
            } else if let Some(error) =
                call.output.and_then(|output| ContractErrorsErrors::abi_decode(&output).ok())
                && matches!(
                    error,
                    ContractErrorsErrors::ERC20InsufficientBalance(_) // OpenZeppelin >= 5.0.0
                        | ContractErrorsErrors::InsufficientBalance(_) // Solady
                        | ContractErrorsErrors::ETHTransferFailed(_) // Solady
                        | ContractErrorsErrors::TransferFailed(_) // Solady
                        | ContractErrorsErrors::TransferFromFailed(_) // Solady
                )
            {
            }
            // TODO: do not hardcode USDT address
            else if to == address!("0xdac17f958d2ee523a2206206994597c13d831ec7")
                && call.error.is_some()
            {
                // USDT transfers just revert on not enough allowance or insufficient funds
            } else {
                continue;
            }

            assets.insert(asset);
            *deficits.entry(from).or_insert_with(HashMap::new).entry(asset).or_default() += amount;
        }

        // Fetch assets metadata
        let mut metadata = self.get_asset_info_list(provider, assets.into_iter().collect()).await?;

        Ok(AssetDeficits(
            deficits
                .into_iter()
                .map(|(address, tokens)| {
                    (
                        address,
                        tokens
                            .into_iter()
                            .map(|(asset, value)| AssetDeficit {
                                address: asset.is_native().not().then(|| asset.address()),
                                token_kind: asset.is_native().not().then_some(AssetType::ERC20),
                                metadata: metadata.remove(&asset).unwrap().metadata,
                                value,
                                fiat: None,
                            })
                            .collect(),
                    )
                })
                .collect(),
        ))
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
    /// Symbols for native assets.
    native_symbols: HashMap<ChainId, String>,
}

impl AssetInfoService {
    /// Creates a new [`AssetInfoService`].
    pub fn new(capacity: u32, config: &RelayConfig) -> Self {
        let (command_tx, command_rx) = unbounded_channel();

        Self {
            cache: LruMap::new(ByLength::new(capacity)),
            command_tx,
            command_rx,
            native_symbols: config
                .chains
                .iter()
                .flat_map(|(chain, conf)| Some((chain.id(), conf.native_symbol.clone()?)))
                .collect(),
        }
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
                        let symbol = self
                            .native_symbols
                            .get(&chain_id)
                            .map(|sym| sym.as_str())
                            .unwrap_or("ETH");

                        Some(AssetWithInfo {
                            asset: Asset::Native,
                            metadata: AssetMetadata {
                                symbol: Some(symbol.to_string()),
                                decimals: Some(18u8),
                                name: None,
                                uri: None,
                            },
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

/// Helper function to decode tokenURI from multicall result
fn decode_token_uri(result: &IMulticall3::Result) -> Option<String> {
    if result.success && !result.returnData.is_empty() {
        IERC721::tokenURICall::abi_decode_returns(&result.returnData).ok()
    } else {
        None
    }
}

/// Gets metadata from many assets on chain.
async fn get_info<P: Provider>(
    provider: &P,
    assets: Vec<Address>,
) -> Result<Vec<AssetWithInfo>, RelayError> {
    let calls = assets
        .iter()
        .flat_map(|asset| {
            [
                Call3 {
                    target: *asset,
                    allowFailure: true,
                    callData: IERC20::decimalsCall::SELECTOR.into(),
                },
                Call3 {
                    target: *asset,
                    allowFailure: true,
                    callData: IERC20::symbolCall::SELECTOR.into(),
                },
                Call3 {
                    target: *asset,
                    allowFailure: true,
                    callData: IERC20::nameCall::SELECTOR.into(),
                },
            ]
        })
        .collect();

    let call_bundle = aggregate3Call::abi_decode_returns(
        &provider
            .call(
                TransactionRequest::default()
                    .to(MULTICALL3_ADDRESS)
                    .input(aggregate3Call { calls }.abi_encode().into()),
            )
            .await?,
    )?;

    if call_bundle.len() != 3 * assets.len() {
        error!(
            "Expected {} responses in multicall but found {}.",
            3 * assets.len(),
            call_bundle.len()
        );
        return Err(AssetError::InvalidAssetInfoResponse.into());
    }

    let mut assets_with_info = Vec::with_capacity(assets.len());
    let mut call_bundle_iter = call_bundle.into_iter();

    for asset in assets {
        let decimals = call_bundle_iter.next().expect("qed");
        let symbol = call_bundle_iter.next().expect("qed");
        let name = call_bundle_iter.next().expect("qed");

        // This can be a non-ERC20 asset or an out of standard one, so we can only attempt to query
        // & decode.
        assets_with_info.push(AssetWithInfo {
            asset: Asset::Token(asset),
            metadata: AssetMetadata {
                decimals: decimals
                    .success
                    .then(|| IERC20::decimalsCall::abi_decode_returns(&decimals.returnData).ok())
                    .flatten(),
                symbol: symbol
                    .success
                    .then(|| IERC20::symbolCall::abi_decode_returns(&symbol.returnData).ok())
                    .flatten(),
                name: name
                    .success
                    .then(|| IERC20::nameCall::abi_decode_returns(&name.returnData).ok())
                    .flatten(),
                uri: None,
            },
        })
    }

    Ok(assets_with_info)
}
