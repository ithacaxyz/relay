//! A container for chain-specific information and RPCs.
use alloy::{
    eips::eip1559::Eip1559Estimation,
    primitives::{Address, Bytes, ChainId, TxHash},
    providers::{Provider, WalletProvider},
    rpc::types::TransactionRequest,
    transports::TransportResult,
};

use crate::types::IERC20;

/// A wrapper around an Alloy provider for signing and sending sponsored transactions.
#[derive(Clone, Debug)]
pub struct Upstream<P> {
    provider: P,
    chain_id: ChainId,
}

impl<P> Upstream<P> {
    /// Get the chain ID of this upstream.
    pub fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Get the inner provider.
    pub fn inner(&self) -> &P {
        &self.provider
    }
}

impl<P> Upstream<P>
where
    P: Provider + WalletProvider,
{
    /// Create a new [`Upstream`]
    pub async fn new(provider: P) -> TransportResult<Self> {
        let chain_id = provider.get_chain_id().await?;
        Ok(Self { chain_id, provider })
    }

    /// Get the address of this upstream's signer.
    pub fn default_signer_address(&self) -> Address {
        self.provider.default_signer_address()
    }

    /// Get the code of the given account.
    pub async fn get_code(&self, address: Address) -> TransportResult<Bytes> {
        self.provider.get_code_at(address).await
    }

    /// Get token decimals from chain.
    pub async fn get_token_decimals(&self, token: Address) -> Result<u8, eyre::Error> {
        Ok(IERC20::new(token, &self.provider).decimals().call().await?._0)
    }

    /// Estimate EIP-1559 fees.
    pub async fn estimate_eip1559(&self) -> TransportResult<Eip1559Estimation> {
        self.provider.estimate_eip1559_fees(None).await
    }

    /// Sign and send the transaction request.
    pub async fn sign_and_send(&self, tx: TransactionRequest) -> TransportResult<TxHash> {
        self.provider.send_transaction(tx).await.map(|pending| *pending.tx_hash())
    }

    /// Get the provider for this upstream.
    pub fn provider(&self) -> &P {
        &self.provider
    }
}
