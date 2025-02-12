//! A container for chain-specific information and RPCs.
use alloy::{
    primitives::{map::AddressMap, Address, Bytes, ChainId, TxHash},
    providers::{Provider, WalletProvider},
    rpc::types::{state::AccountOverride, TransactionRequest},
    sol_types::SolCall,
    transports::TransportResult,
};

use crate::{
    error::CallError,
    types::{Eip1559Estimation, IERC20},
};

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

    /// Perform an `eth_call`.
    pub async fn call<C: SolCall>(&self, tx: &TransactionRequest) -> Result<C::Return, CallError> {
        self.call_with_overrides::<C>(tx, &AddressMap::from_iter([])).await
    }

    /// Perform an `eth_call` with overrides.
    pub async fn call_with_overrides<C: SolCall>(
        &self,
        tx: &TransactionRequest,
        overrides: &AddressMap<AccountOverride>,
    ) -> Result<C::Return, CallError> {
        self.provider
            .call(tx)
            .overrides(overrides)
            .await
            .map_err(Into::into)
            .and_then(|r| C::abi_decode_returns(&r[..], false).map_err(Into::into))
    }

    /// Estimate EIP-1559 fees.
    pub async fn estimate_eip1559(&self) -> TransportResult<Eip1559Estimation> {
        self.provider.estimate_eip1559_fees(None).await.map(Into::into)
    }

    /// Sign and send the transaction request.
    pub async fn sign_and_send(&self, tx: TransactionRequest) -> TransportResult<TxHash> {
        self.provider.send_transaction(tx).await.map(|pending| *pending.tx_hash())
    }
}
