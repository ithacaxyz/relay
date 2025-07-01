use crate::{
    liquidity::{
        bridge::{
            Bridge, BridgeEvent, Transfer, TransferState,
            simple::Funder::{pullGasCall, withdrawTokensCall},
        },
        tracker::ChainAddress,
    },
    signers::DynSigner,
    storage::{RelayStorage, StorageApi},
    types::IERC20::transferCall,
};
use alloy::{
    consensus::{SignableTransaction, Signed, TxEip1559},
    eips::Encodable2718,
    primitives::{Address, Bytes, ChainId, U256},
    providers::{DynProvider, PendingTransactionBuilder, Provider},
    rpc::types::{TransactionReceipt, TransactionRequest},
    sol,
    sol_types::SolCall,
};
use eyre::OptionExt;
use futures_util::Stream;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::sync::mpsc;
use tracing::error;

sol! {
    contract Funder {
        function withdrawTokens(address token, address recipient, uint256 amount) external;
        function pullGas(uint256 amount) external;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SimpleBridgeData {
    outbound_tx: Option<Signed<TxEip1559>>,
    inbound_tx: Option<Signed<TxEip1559>>,
}

#[derive(Debug)]
struct SimpleBridgeInner {
    providers: HashMap<ChainId, DynProvider>,
    signer: DynSigner,
    funder_address: Address,
    storage: RelayStorage,
    events_tx: mpsc::UnboundedSender<BridgeEvent>,
}

impl SimpleBridgeInner {
    async fn build_tx(
        &self,
        chain_id: ChainId,
        to: Address,
        input: Bytes,
        value: U256,
    ) -> eyre::Result<Signed<TxEip1559>> {
        let Some(provider) = self.providers.get(&chain_id).cloned() else {
            eyre::bail!("provider not found for chain");
        };

        let nonce = provider.get_transaction_count(self.signer.address()).await?;
        let fees = provider.estimate_eip1559_fees().await?;

        let gas_limit = provider
            .estimate_gas(
                TransactionRequest::default()
                    .to(to)
                    .input(input.clone().into())
                    .value(value)
                    .from(self.signer.address()),
            )
            .await?;

        let mut tx = TxEip1559 {
            chain_id,
            nonce,
            gas_limit,
            max_fee_per_gas: fees.max_fee_per_gas,
            max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
            to: to.into(),
            input,
            value,
            ..Default::default()
        };

        let signature = self.signer.sign_transaction(&mut tx).await?;
        Ok(tx.into_signed(signature))
    }

    async fn send_tx(&self, tx: &Signed<TxEip1559>) -> eyre::Result<TransactionReceipt> {
        let Some(provider) = self.providers.get(&tx.tx().chain_id).cloned() else {
            eyre::bail!("provider not found for chain");
        };

        let _ = provider.send_raw_transaction(&tx.encoded_2718()).await?;

        let receipt = PendingTransactionBuilder::new(provider.root().clone(), *tx.hash())
            .get_receipt()
            .await?;

        if !receipt.status() {
            return Err(eyre::eyre!("transfer failed"));
        }

        Ok(receipt)
    }

    async fn save_bridge_data(
        &self,
        transfer: &Transfer,
        data: &SimpleBridgeData,
    ) -> eyre::Result<()> {
        let json_data = serde_json::to_value(data)?;
        self.storage.update_transfer_bridge_data(transfer.id, &json_data).await?;
        Ok(())
    }

    async fn load_bridge_data(&self, transfer: &Transfer) -> eyre::Result<SimpleBridgeData> {
        if let Some(data) = self.storage.get_transfer_bridge_data(transfer.id).await? {
            Ok(serde_json::from_value(data)?)
        } else {
            Ok(SimpleBridgeData { outbound_tx: None, inbound_tx: None })
        }
    }

    async fn update_state(&self, transfer: &Transfer, state: TransferState) -> eyre::Result<()> {
        let _ = self.events_tx.send(BridgeEvent::TransferState(transfer.id, state));
        Ok(())
    }

    async fn handle_outbound_tx(
        &self,
        transfer: &Transfer,
        bridge_data: &mut SimpleBridgeData,
    ) -> eyre::Result<u64> {
        // get or prepare outbound transaction
        let oubound_tx = match &mut bridge_data.outbound_tx {
            Some(tx) => tx,
            // If the tx is not yet created, build and save it.
            None => {
                let input = if !transfer.from.1.is_zero() {
                    withdrawTokensCall {
                        token: transfer.from.1,
                        recipient: self.signer.address(),
                        amount: transfer.amount,
                    }
                    .abi_encode()
                } else {
                    pullGasCall { amount: transfer.amount }.abi_encode()
                };

                bridge_data.outbound_tx = Some(
                    self.build_tx(transfer.from.0, self.funder_address, input.into(), U256::ZERO)
                        .await?,
                );

                self.save_bridge_data(transfer, bridge_data).await?;

                bridge_data.outbound_tx.as_mut().unwrap()
            }
        };

        // send and wait for outbound transaction
        let receipt = self.send_tx(oubound_tx).await?;

        Ok(receipt.block_number.unwrap_or_default())
    }

    async fn handle_inbound_tx(
        &self,
        transfer: &Transfer,
        bridge_data: &mut SimpleBridgeData,
    ) -> eyre::Result<u64> {
        let inbound_tx = match &mut bridge_data.inbound_tx {
            Some(tx) => tx,
            None => {
                let tx = if !transfer.to.1.is_zero() {
                    self.build_tx(
                        transfer.to.0,
                        transfer.to.1,
                        transferCall { to: self.funder_address, amount: transfer.amount }
                            .abi_encode()
                            .into(),
                        U256::ZERO,
                    )
                    .await?
                } else {
                    self.build_tx(
                        transfer.to.0,
                        self.funder_address,
                        pullGasCall { amount: transfer.amount }.abi_encode().into(),
                        U256::ZERO,
                    )
                    .await?
                };

                bridge_data.inbound_tx = Some(tx);
                self.save_bridge_data(transfer, bridge_data).await?;
                bridge_data.inbound_tx.as_mut().unwrap()
            }
        };

        // send and wait for inbound transaction
        let receipt = self.send_tx(inbound_tx).await?;

        Ok(receipt.block_number.unwrap_or_default())
    }

    async fn advance_transfer(&self, transfer: Transfer) -> eyre::Result<()> {
        let mut bridge_data = self.load_bridge_data(&transfer).await?;
        let mut state =
            self.storage.get_transfer_state(transfer.id).await?.ok_or_eyre("transfer not found")?;

        loop {
            match state {
                TransferState::Pending => {
                    match self.handle_outbound_tx(&transfer, &mut bridge_data).await {
                        Ok(block_number) => {
                            state = TransferState::Sent(block_number);
                        }
                        Err(e) => {
                            error!("Failed to handle outbound tx: {}", e);
                            state = TransferState::OutboundFailed;
                        }
                    }

                    self.update_state(&transfer, state).await?;
                }
                TransferState::Sent(_) => {
                    state = match self.handle_inbound_tx(&transfer, &mut bridge_data).await {
                        Ok(block_number) => TransferState::Completed(block_number),
                        Err(e) => {
                            error!("Failed to handle inbound tx: {}", e);
                            TransferState::InboundFailed
                        }
                    };

                    self.update_state(&transfer, state).await?;
                }
                TransferState::OutboundFailed
                | TransferState::InboundFailed
                | TransferState::Completed(_) => break,
            }
        }

        Ok(())
    }
}

/// Simple bridge implementation which assumes that signer address is funded on all chains.
#[derive(Debug)]
pub struct SimpleBridge {
    inner: Arc<SimpleBridgeInner>,
    events_rx: mpsc::UnboundedReceiver<BridgeEvent>,
}

impl SimpleBridge {
    /// Creates a new SimpleBridge instance.
    pub fn new(
        providers: HashMap<ChainId, DynProvider>,
        signer: DynSigner,
        funder_address: Address,
        storage: RelayStorage,
    ) -> Self {
        let (events_tx, events_rx) = mpsc::unbounded_channel();

        let inner = SimpleBridgeInner { providers, signer, funder_address, storage, events_tx };

        Self { inner: Arc::new(inner), events_rx }
    }
}

impl Stream for SimpleBridge {
    type Item = BridgeEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.events_rx.poll_recv(cx)
    }
}

impl Bridge for SimpleBridge {
    fn id(&self) -> &'static str {
        "simple"
    }

    fn supports(&self, _src: ChainAddress, _dst: ChainAddress) -> bool {
        true
    }

    fn advance(&mut self, transfer: Transfer) {
        let this = self.inner.clone();
        tokio::spawn(async move {
            if let Err(e) = this.advance_transfer(transfer).await {
                tracing::error!("Failed to advance transfer: {}", e);
            }
        });
    }
}
