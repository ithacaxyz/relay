use crate::{
    liquidity::{
        ChainAddress,
        bridge::{Bridge, BridgeEvent, BridgeTransfer, BridgeTransferState},
    },
    signers::DynSigner,
    storage::{RelayStorage, StorageApi},
    transactions::{RelayTransaction, TransactionServiceHandle, TransactionStatus},
    types::{FeeTokens, Funder},
};
use alloy::{
    primitives::{Address, B256, ChainId, U256, map::HashMap},
    providers::{DynProvider, Provider},
    sol_types::SolCall,
};
use alloy_chains::{Chain, NamedChain};
use binance_sdk::{
    config::ConfigurationRestApi,
    wallet::{
        WalletRestApi,
        rest_api::{
            DepositAddressParams, DepositHistoryParams, RestApi, WithdrawHistoryParams,
            WithdrawHistoryResponseInner, WithdrawParams,
        },
    },
};
use eyre::OptionExt;
use futures_util::Stream;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::{
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::mpsc;
use tracing::{error, warn};

fn binance_network_to_chain(network: &str) -> Option<Chain> {
    match network {
        "ETH" => Some(Chain::mainnet()),
        "BASE" => Some(Chain::base_mainnet()),
        "ARBITRUM" => Some(Chain::arbitrum_mainnet()),
        "OPTIMISM" => Some(Chain::optimism_mainnet()),
        "BSC" => Some(Chain::bsc_mainnet()),
        "MATIC" => Some(Chain::from_named(NamedChain::Polygon)),
        _ => None,
    }
}

/// Maps Binance network ID to the Binance coin ID for the native token on this chain.
fn binance_network_to_native_coin(network: &str) -> Option<&'static str> {
    match network {
        "ETH" => Some("ETH"),
        "BASE" => Some("ETH"),
        "ARBITRUM" => Some("ETH"),
        "OPTIMISM" => Some("ETH"),
        "BSC" => Some("BNB"),
        "MATIC" => Some("POL"),
        _ => None,
    }
}

/// Metadata needed to create [`WithdrawParams`] for a token.
#[derive(Debug, Clone)]
struct WithdrawTokenData {
    name: String,
    network: String,
    token_decimals: u8,
    withdraw_decimals: u8,
}

/// Configuration for the [`BinanceBridge`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinanceBridgeConfig {
    /// Binance API key.
    pub api_key: String,
    /// Binance API secret.
    pub api_secret: String,
}

/// [`Bridge`] implementation that bridges tokens by depositing and then withdrawing from Binance.
#[must_use = "Stream does nothing unless polled"]
#[derive(Debug)]
pub struct BinanceBridge {
    inner: Arc<BinanceBridgeInner>,
    events_rx: mpsc::UnboundedReceiver<BridgeEvent>,
}

impl BinanceBridge {
    /// Create a new [`BinanceBridge`] instance.
    pub async fn new(
        providers: HashMap<ChainId, DynProvider>,
        tx_services: HashMap<ChainId, TransactionServiceHandle>,
        config: BinanceBridgeConfig,
        fee_tokens: &FeeTokens,
        storage: RelayStorage,
        funder_address: Address,
        funder_owner: DynSigner,
    ) -> eyre::Result<Self> {
        // Build Binance client.
        let client = WalletRestApi::production(
            ConfigurationRestApi::builder()
                .api_key(config.api_key)
                .api_secret(config.api_secret)
                .build()
                .map_err(|e| eyre::eyre!("Failed to build Binance client: {}", e))?,
        );

        // Collect deposit addresses and supported withdrawal networks.
        let mut deposit_addresses = HashMap::default();
        let mut supported_withdrawals = HashMap::default();

        let coins = client
            .all_coins_information(Default::default())
            .await
            .map_err(|e| eyre::eyre!(Box::new(e)))?
            .data()
            .await?;

        // Go over all coins and find the ones we are interested in.
        for coin in coins {
            let Some(coin_name) = &coin.coin else {
                continue;
            };

            let Some(networks) = &coin.network_list else {
                continue;
            };

            // Iterate over all supported networks for the coin.
            for network in networks {
                let Some(network_name) = &network.network else {
                    continue;
                };

                // Try to parse the network into supported chain.
                let Some(chain) = binance_network_to_chain(network_name) else {
                    continue;
                };

                let Some(contract_address) = network
                    .contract_address
                    .as_ref()
                    .and_then(|addr| Address::from_str(addr).ok())
                    .or_else(|| {
                        if binance_network_to_native_coin(network_name)
                            .is_some_and(|native| native == coin_name)
                        {
                            Some(Address::ZERO)
                        } else {
                            None
                        }
                    })
                else {
                    continue;
                };

                // Find whether this coin is supported for interop on the given chain.
                let Some(token) =
                    fee_tokens.find(chain.id(), &contract_address).filter(|t| t.interop)
                else {
                    continue;
                };

                // If deposits are supported, fetch deposit address.
                if network.deposit_enable.is_some_and(|enable| enable)
                    && let Some(deposit_address) = client
                        .deposit_address(
                            DepositAddressParams::builder(coin_name.clone())
                                .network(network_name.clone())
                                .build()
                                .map_err(|e| {
                                    eyre::eyre!("Failed to build DepositAddressParams: {}", e)
                                })?,
                        )
                        .await
                        .map_err(|e| eyre::eyre!("Failed to get deposit address: {}", e))?
                        .data()
                        .await?
                        .address
                        .as_deref()
                        .map(Address::from_str)
                        .transpose()?
                {
                    deposit_addresses.insert((chain.id(), contract_address), deposit_address);
                }

                // If withdrawals are supported, fetch neccesary context.
                if network.withdraw_enable.is_some_and(|enable| enable) {
                    // This represents amount of decimals accepted by Binance for withdrawal amount.
                    let withdraw_decimals =
                        if let Some(withdraw_decimals) = &network.withdraw_integer_multiple {
                            if withdraw_decimals.starts_with("0.") {
                                (withdraw_decimals.len() - 2) as u8
                            } else {
                                continue;
                            }
                        } else {
                            continue;
                        };

                    supported_withdrawals.insert(
                        (chain.id(), contract_address),
                        WithdrawTokenData {
                            name: coin_name.clone(),
                            network: network_name.clone(),
                            token_decimals: token.decimals,
                            withdraw_decimals,
                        },
                    );
                }
            }
        }

        let (events_tx, events_rx) = mpsc::unbounded_channel();

        Ok(Self {
            inner: Arc::new(BinanceBridgeInner {
                client,
                deposit_addresses,
                supported_withdrawals,
                storage,
                funder_address,
                events_tx,
                providers,
                funder_owner,
                tx_services,
            }),
            events_rx,
        })
    }
}

impl Stream for BinanceBridge {
    type Item = BridgeEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.events_rx.poll_recv(cx)
    }
}

impl Bridge for BinanceBridge {
    fn id(&self) -> &'static str {
        "binance"
    }

    fn supports(&self, src: ChainAddress, dst: ChainAddress) -> bool {
        self.inner.deposit_addresses.contains_key(&src)
            && self.inner.supported_withdrawals.contains_key(&dst)
    }

    fn process(&self, transfer: BridgeTransfer) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let this = self.inner.clone();

        Box::pin(async move {
            if let Err(e) = this.advance_transfer(transfer).await {
                error!("Failed to advance transfer: {}", e);
            }
        })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct BinanceBridgeData {
    deposit_tx: Option<RelayTransaction>,
    deposit_tx_hash: Option<B256>,
    withdrawal_id: Option<String>,
}

#[derive(Debug)]
pub struct BinanceBridgeInner {
    client: RestApi,
    providers: HashMap<ChainId, DynProvider>,
    tx_services: HashMap<ChainId, TransactionServiceHandle>,
    deposit_addresses: HashMap<ChainAddress, Address>,
    supported_withdrawals: HashMap<ChainAddress, WithdrawTokenData>,
    storage: RelayStorage,
    funder_address: Address,
    funder_owner: DynSigner,
    events_tx: mpsc::UnboundedSender<BridgeEvent>,
}

impl BinanceBridgeInner {
    /// Loads [`BinanceBridgeData`] for a given transfer.
    async fn load_bridge_data(&self, transfer: &BridgeTransfer) -> eyre::Result<BinanceBridgeData> {
        if let Some(bridge_data) = self.storage.get_transfer_bridge_data(transfer.id).await? {
            Ok(serde_json::from_value(bridge_data)?)
        } else {
            Ok(BinanceBridgeData::default())
        }
    }

    /// Saves [`BinanceBridgeData`] for a given transfer.
    async fn save_bridge_data(
        &self,
        transfer: &BridgeTransfer,
        data: &BinanceBridgeData,
    ) -> eyre::Result<()> {
        let json_data = serde_json::to_value(data)?;
        self.storage.update_transfer_bridge_data(transfer.id, &json_data).await?;
        Ok(())
    }

    /// Sends a deposit transaction for a given transfer, updates [`BinanceBridgeData`] with the
    /// deposit transaction hash.
    async fn send_deposit(
        &self,
        transfer: &BridgeTransfer,
        bridge_data: &mut BinanceBridgeData,
    ) -> eyre::Result<u64> {
        // Send or load previously sent deposit transaction.
        let deposit_tx = if let Some(deposit_tx) = &bridge_data.deposit_tx {
            deposit_tx
        } else {
            let Some(deposit_address) = self.deposit_addresses.get(&transfer.from) else {
                return Err(eyre::eyre!("No deposit address found for source chain"));
            };

            // Prepare calldata for the funder.
            let input = Funder::new(self.funder_address, &self.providers[&transfer.from.0])
                .withdrawal_call(
                    transfer.from.1,
                    *deposit_address,
                    transfer.amount,
                    &self.funder_owner,
                )
                .await?
                .abi_encode();

            bridge_data.deposit_tx = Some(RelayTransaction::new_internal(
                self.funder_address,
                input,
                transfer.from.0,
                1_000_000,
            ));

            self.save_bridge_data(transfer, bridge_data).await?;

            bridge_data.deposit_tx.as_ref().unwrap()
        };

        let tx_service = &self.tx_services[&transfer.from.0];

        // Send the transaction if it's not already sent.
        if self.storage.read_transaction_status(deposit_tx.id).await?.is_none() {
            tx_service.send_transaction(deposit_tx.clone()).await?;
        }

        let status = tx_service.wait_for_tx(deposit_tx.id).await?;
        let TransactionStatus::Confirmed(receipt) = status else {
            eyre::bail!("deposit transaction failed: {:?}", status);
        };

        bridge_data.deposit_tx_hash = Some(receipt.transaction_hash);
        self.save_bridge_data(transfer, bridge_data).await?;

        Ok(receipt.block_number.unwrap_or_default())
    }

    /// Fetches a withdrawal for a given transfer. We are using [`BridgeTransfer::id`] as a
    /// withdrawal client-side ID ([`WithdrawHistoryParams::withdraw_order_id`]), allowing us to
    /// have a 1:1 mapping between transfers and withdrawals.
    async fn find_withdrawal(
        &self,
        transfer: &BridgeTransfer,
    ) -> eyre::Result<Option<WithdrawHistoryResponseInner>> {
        let mut withdrawals = self
            .client
            .withdraw_history(
                WithdrawHistoryParams::builder()
                    .withdraw_order_id(transfer.id.to_string())
                    .build()
                    .unwrap(),
            )
            .await
            .map_err(|e| eyre::eyre!(Box::new(e)))?
            .data()
            .await?;

        Ok(withdrawals.pop())
    }

    /// Waits for a deposit to be completed and then sends a withdrawal.
    async fn wait_for_deposit_and_withdraw(
        &self,
        transfer: &BridgeTransfer,
        bridge_data: &mut BinanceBridgeData,
    ) -> eyre::Result<u64> {
        let Some(deposit_tx_hash) = &bridge_data.deposit_tx_hash else {
            // should be unreachable
            return Err(eyre::eyre!("No deposit tx for sent transfer"));
        };

        // Wait for deposit to be completed
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;

            let mut deposit_history = self
                .client
                .deposit_history(DepositHistoryParams {
                    tx_id: Some(deposit_tx_hash.to_string()),
                    ..Default::default()
                })
                .await
                .map_err(|e| eyre::eyre!("Failed to get deposit history: {}", e))?
                .data()
                .await?;

            let Some(deposit) = deposit_history.pop() else {
                continue;
            };

            if deposit.complete_time.is_none() {
                continue;
            } else {
                break;
            }
        }

        // Send withdrawal if it's not sent already.
        if self.find_withdrawal(transfer).await?.is_none() {
            let Some(WithdrawTokenData { name, network, token_decimals, withdraw_decimals }) =
                self.supported_withdrawals.get(&transfer.from)
            else {
                return Err(eyre::eyre!("No supported withdrawal for source chain"));
            };

            let amount = Decimal::try_from_i128_with_scale(
                transfer
                    .amount
                    // Scale the amount down to the precision accepted by Binance.
                    .wrapping_div(U256::from(
                        10u128.pow((token_decimals - withdraw_decimals) as u32),
                    ))
                    .to(),
                *withdraw_decimals as u32,
            )?;

            // Send the withdrawal.
            // We are assigning a client side ID here to be able to lookup it later without dealing
            // with Binance server-side IDs.
            self.client
                .withdraw(
                    WithdrawParams::builder(name.clone(), self.funder_address.to_string(), amount)
                        .network(network.clone())
                        .withdraw_order_id(transfer.id.to_string())
                        .build()
                        .unwrap(),
                )
                .await
                .map_err(|e| eyre::eyre!(Box::new(e)))?
                .data()
                .await?
                .id
                .ok_or_eyre("failed to withdraw funds")?;
        };

        let Some(provider) = self.providers.get(&transfer.to.0) else {
            // should be unreachable
            eyre::bail!("unknown chain")
        };

        // Wait for the withdrawal to be completed.
        loop {
            // Fetch the withdrawal.
            let withdrawal =
                self.find_withdrawal(transfer).await?.ok_or_eyre("failed to fetch withdrawal")?;

            // If we already have a transaction hash, just wait for it to be confirmed.
            if let Some(tx_id) = withdrawal.tx_id {
                let tx_id = B256::from_str(&tx_id)?;
                if let Some(receipt) = provider.get_transaction_receipt(tx_id).await? {
                    break Ok(receipt.block_number.unwrap_or_default());
                }
            }

            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    }

    /// Advances the transfer state by sending a deposit and immediately withdrawing the funds.
    async fn advance_transfer(&self, transfer: BridgeTransfer) -> eyre::Result<()> {
        let mut bridge_data = self.load_bridge_data(&transfer).await?;
        let mut state =
            self.storage.get_transfer_state(transfer.id).await?.ok_or_eyre("transfer not found")?;

        loop {
            match state {
                BridgeTransferState::Pending => {
                    match self.send_deposit(&transfer, &mut bridge_data).await {
                        Ok(block_number) => {
                            state = BridgeTransferState::Sent(block_number);
                        }
                        Err(err) => {
                            warn!(%err, "failed to send deposit");
                            state = BridgeTransferState::OutboundFailed;
                        }
                    }
                    let _ = self.events_tx.send(BridgeEvent::TransferState(transfer.id, state));
                }
                BridgeTransferState::Sent(_) => {
                    match self.wait_for_deposit_and_withdraw(&transfer, &mut bridge_data).await {
                        Ok(block_number) => {
                            state = BridgeTransferState::Completed(block_number);
                        }
                        Err(err) => {
                            warn!(%err, "failed to withdraw");
                            state = BridgeTransferState::InboundFailed;
                        }
                    }
                    let _ = self.events_tx.send(BridgeEvent::TransferState(transfer.id, state));
                }
                _ => break Ok(()),
            }
        }
    }
}
