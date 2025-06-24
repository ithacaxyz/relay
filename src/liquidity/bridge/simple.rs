use std::{
    collections::HashMap,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use crate::{
    liquidity::bridge::{
        Bridge, BridgeEvent, Transfer, TransferId,
        simple::Funder::{pullGasCall, withdrawTokensCall},
    },
    signers::DynSigner,
    types::{CoinKind, CoinRegistry, IERC20::transferCall},
};
use alloy::{
    consensus::{SignableTransaction, TxEip1559, TxEnvelope},
    primitives::{Address, B256, Bytes, ChainId, U256},
    providers::{DynProvider, Provider},
    rpc::types::TransactionReceipt,
    sol,
    sol_types::SolCall,
};
use futures_util::Stream;
use tokio::sync::mpsc;

sol! {
    contract Funder {
        function withdrawTokens(address token, address recipient, uint256 amount) external;
        function pullGas(uint256 amount) external;
    }
}

#[derive(Debug)]
struct SimpleBridgeInner {
    registry: Arc<CoinRegistry>,
    providers: HashMap<ChainId, DynProvider>,
    signer: DynSigner,
    funder_address: Address,
    events_tx: mpsc::UnboundedSender<BridgeEvent>,
}

impl SimpleBridgeInner {
    async fn send_tx(
        &self,
        chain_id: ChainId,
        to: Address,
        input: Bytes,
        value: U256,
    ) -> eyre::Result<TransactionReceipt> {
        let Some(provider) = self.providers.get(&chain_id).cloned() else {
            eyre::bail!("provider not found for chain");
        };

        let nonce = provider.get_transaction_count(self.signer.address()).await?;
        let fees = provider.estimate_eip1559_fees().await?;

        let mut tx = TxEip1559 {
            chain_id,
            nonce,
            gas_limit: 100_000,
            max_fee_per_gas: fees.max_fee_per_gas,
            max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
            to: to.into(),
            input,
            value,
            ..Default::default()
        };

        let signature = self.signer.sign_transaction(&mut tx).await?;
        let tx = TxEnvelope::Eip1559(tx.into_signed(signature));

        let receipt = provider.send_tx_envelope(tx).await?.get_receipt().await?;

        if !receipt.status() {
            return Err(eyre::eyre!("transfer failed"));
        }

        Ok(receipt)
    }

    async fn send_funds(
        &self,
        chain_id: ChainId,
        address: Option<Address>,
        amount: U256,
    ) -> eyre::Result<TransactionReceipt> {
        if let Some(token) = address {
            self.send_tx(
                chain_id,
                token,
                transferCall { to: self.funder_address, amount }.abi_encode().into(),
                U256::ZERO,
            )
            .await
        } else {
            self.send_tx(chain_id, self.funder_address, Default::default(), amount).await
        }
    }
}

#[derive(Debug)]
pub struct SimpleBridge {
    inner: Arc<SimpleBridgeInner>,
    events_rx: mpsc::UnboundedReceiver<BridgeEvent>,
    transfers_in_progress: Vec<Transfer>,
}

impl SimpleBridge {
    /// Creates a new SimpleBridge instance.
    pub fn new(
        registry: Arc<CoinRegistry>,
        providers: HashMap<ChainId, DynProvider>,
        signer: DynSigner,
        funder_address: Address,
    ) -> Self {
        let (events_tx, events_rx) = mpsc::unbounded_channel();

        let inner = SimpleBridgeInner { registry, providers, signer, funder_address, events_tx };

        Self { inner: Arc::new(inner), events_rx, transfers_in_progress: Default::default() }
    }
}

impl Stream for SimpleBridge {
    type Item = BridgeEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.events_rx.poll_recv(cx).map(|item| {
            if let Some(event) = &item {
                match event {
                    BridgeEvent::TransferSent(_, _) => {}
                    BridgeEvent::InboundFailed(transfer)
                    | BridgeEvent::OutboundFailed(transfer)
                    | BridgeEvent::TransferCompleted(transfer, _) => {
                        self.transfers_in_progress.retain(|t| t.id != transfer.id);
                    }
                }
            }

            item
        })
    }
}

impl Bridge for SimpleBridge {
    fn supports(&self, _kind: CoinKind, _from: ChainId, _to: ChainId) -> bool {
        true
    }

    fn send(
        &mut self,
        kind: CoinKind,
        amount: U256,
        from: ChainId,
        to: ChainId,
    ) -> eyre::Result<()> {
        let Some(address) = self.inner.registry.address(kind, from) else {
            eyre::bail!("coin not found in registry");
        };

        let transfer = Transfer {
            id: TransferId(B256::random()),
            kind,
            address: address.unwrap_or_default(),
            amount,
            from,
            to,
        };
        self.transfers_in_progress.push(transfer);

        let this = self.inner.clone();
        tokio::spawn(async move {
            let input = if let Some(token) = address {
                withdrawTokensCall { token, recipient: this.signer.address(), amount }.abi_encode()
            } else {
                pullGasCall { amount }.abi_encode()
            };

            let Ok(receipt) =
                this.send_tx(from, this.funder_address, input.into(), U256::ZERO).await
            else {
                let _ = this.events_tx.send(BridgeEvent::OutboundFailed(transfer));
                return;
            };

            let _ = this.events_tx.send(BridgeEvent::TransferSent(
                transfer,
                receipt.block_number.unwrap_or_default(),
            ));

            let Ok(receipt) = this.send_funds(to, address, amount).await else {
                let _ = this.events_tx.send(BridgeEvent::InboundFailed(transfer));
                return;
            };

            let _ = this.events_tx.send(BridgeEvent::TransferCompleted(
                transfer,
                receipt.block_number.unwrap_or_default(),
            ));
        });

        Ok(())
    }

    fn transfers_in_progress(&self) -> &[Transfer] {
        &self.transfers_in_progress
    }
}
