use crate::{
    liquidity::{
        bridge::{Bridge, BridgeEvent, BridgeTransfer, BridgeTransferState},
        tracker::ChainAddress,
    },
    signers::DynSigner,
    storage::{RelayStorage, StorageApi},
    transactions::{RelayTransaction, TransactionServiceHandle, TransactionStatus},
    types::{Funder, IERC20::transferCall},
};
use alloy::{
    consensus::{SignableTransaction, Signed, TxEip1559},
    eips::Encodable2718,
    primitives::{Address, Bytes, ChainId, U256},
    providers::{DynProvider, PendingTransactionBuilder, Provider},
    rpc::types::{TransactionReceipt, TransactionRequest},
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
        tx_services: HashMap<ChainId, TransactionServiceHandle>,
        signer: DynSigner,
        funder_address: Address,
        storage: RelayStorage,
        funder_owner: DynSigner,
    ) -> Self {
        let (events_tx, events_rx) = mpsc::unbounded_channel();

        let inner = SimpleBridgeInner {
            providers,
            tx_services,
            signer,
            funder_address,
            storage,
            events_tx,
            funder_owner,
        };

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

    fn process(&self, transfer: BridgeTransfer) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let this = self.inner.clone();
        Box::pin(async move {
            if let Err(e) = this.advance_transfer(transfer).await {
                error!("Failed to advance transfer: {}", e);
            }
        })
    }
}

#[derive(Debug)]
struct SimpleBridgeInner {
    providers: HashMap<ChainId, DynProvider>,
    tx_services: HashMap<ChainId, TransactionServiceHandle>,
    signer: DynSigner,
    funder_address: Address,
    storage: RelayStorage,
    events_tx: mpsc::UnboundedSender<BridgeEvent>,
    funder_owner: DynSigner,
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

    /// Saves [`SimpleBridgeData`] for a transfer.
    async fn save_bridge_data(
        &self,
        transfer: &BridgeTransfer,
        data: &SimpleBridgeData,
    ) -> eyre::Result<()> {
        let json_data = serde_json::to_value(data)?;
        self.storage.update_transfer_bridge_data(transfer.id, &json_data).await?;
        Ok(())
    }

    /// Loads [`SimpleBridgeData`] for a transfer. If it's not found, returns a default value.
    async fn load_bridge_data(&self, transfer: &BridgeTransfer) -> eyre::Result<SimpleBridgeData> {
        if let Some(data) = self.storage.get_transfer_bridge_data(transfer.id).await? {
            Ok(serde_json::from_value(data)?)
        } else {
            Ok(SimpleBridgeData { outbound_tx: None, inbound_tx: None })
        }
    }

    /// Handles outbound transaction. This essentially means pulling the tokens from the funder on
    /// the source chain.
    ///
    /// This method will build transaction and save it to database as part of [`SimpleBridgeData`],
    /// and then wait for it to land.
    async fn handle_outbound_tx(
        &self,
        transfer: &BridgeTransfer,
        bridge_data: &mut SimpleBridgeData,
    ) -> eyre::Result<u64> {
        // get or prepare outbound transaction
        let oubound_tx = match &bridge_data.outbound_tx {
            Some(tx) => tx,
            // If the tx is not yet created, build and save it.
            None => {
                let input = Funder::new(self.funder_address, &self.providers[&transfer.from.0])
                    .withdrawal_call(
                        transfer.from.1,
                        self.signer.address(),
                        transfer.amount,
                        &self.funder_owner,
                    )
                    .await?
                    .abi_encode();

                bridge_data.outbound_tx = Some(RelayTransaction::new_internal(
                    self.funder_address,
                    input,
                    transfer.from.0,
                    1_000_000,
                ));

                self.save_bridge_data(transfer, bridge_data).await?;

                bridge_data.outbound_tx.as_ref().unwrap()
            }
        };

        let tx_service = &self.tx_services[&transfer.from.0];

        if self.storage.read_transaction_status(oubound_tx.id).await?.is_none() {
            tx_service.send_transaction(oubound_tx.clone()).await?;
        }

        // send and wait for outbound transaction
        let status = tx_service.wait_for_tx(oubound_tx.id).await?;
        let TransactionStatus::Confirmed(receipt) = status else {
            eyre::bail!("outbound transaction failed: {:?}", status);
        };

        Ok(receipt.block_number.unwrap_or_default())
    }

    /// This is invoked once we know that the outbound transaction has landed.
    ///
    /// Handles inbound transaction, which means sending the tokens to the recipient on the
    /// destination chain.
    async fn handle_inbound_tx(
        &self,
        transfer: &BridgeTransfer,
        bridge_data: &mut SimpleBridgeData,
    ) -> eyre::Result<u64> {
        let inbound_tx = match &bridge_data.inbound_tx {
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
                        Default::default(),
                        transfer.amount,
                    )
                    .await?
                };

                bridge_data.inbound_tx = Some(tx);
                self.save_bridge_data(transfer, bridge_data).await?;
                bridge_data.inbound_tx.as_ref().unwrap()
            }
        };

        // send and wait for inbound transaction
        let receipt = self.send_tx(inbound_tx).await?;

        Ok(receipt.block_number.unwrap_or_default())
    }

    async fn advance_transfer(&self, transfer: BridgeTransfer) -> eyre::Result<()> {
        let mut bridge_data = self.load_bridge_data(&transfer).await?;
        let mut state =
            self.storage.get_transfer_state(transfer.id).await?.ok_or_eyre("transfer not found")?;

        loop {
            match state {
                BridgeTransferState::Pending => {
                    match self.handle_outbound_tx(&transfer, &mut bridge_data).await {
                        Ok(block_number) => {
                            state = BridgeTransferState::Sent(block_number);
                        }
                        Err(e) => {
                            error!("Failed to handle outbound tx: {}", e);
                            state = BridgeTransferState::OutboundFailed;
                        }
                    }

                    let _ = self.events_tx.send(BridgeEvent::TransferState(transfer.id, state));
                }
                BridgeTransferState::Sent(_) => {
                    state = match self.handle_inbound_tx(&transfer, &mut bridge_data).await {
                        Ok(block_number) => BridgeTransferState::Completed(block_number),
                        Err(e) => {
                            error!("Failed to handle inbound tx: {}", e);
                            BridgeTransferState::InboundFailed
                        }
                    };

                    let _ = self.events_tx.send(BridgeEvent::TransferState(transfer.id, state));
                }
                BridgeTransferState::OutboundFailed
                | BridgeTransferState::InboundFailed
                | BridgeTransferState::Completed(_) => break,
            }
        }

        Ok(())
    }
}

/// State of a transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SimpleBridgeData {
    /// Outbound transaction.
    outbound_tx: Option<RelayTransaction>,
    /// Inbound transaction.
    inbound_tx: Option<Signed<TxEip1559>>,
}
