//! A container for chain-specific information and RPCs.
use alloy::{
    primitives::{map::AddressMap, Address, Bytes, ChainId, TxHash},
    providers::{utils::Eip1559Estimation, Provider, WalletProvider},
    rpc::types::{state::AccountOverride, TransactionRequest},
    sol_types::SolCall,
};

use crate::{
    error::{SendActionError, UpstreamError},
    types::IERC20,
};

/// A transport result is a Result containing a UpstreamError.
pub type UpstreamResult<T> = Result<T, UpstreamError>;

/// A wrapper around an Alloy provider for signing and sending sponsored transactions.
#[derive(Clone, Debug)]
pub struct Upstream<P> {
    provider: P,
    chain_id: ChainId,
    entrypoint: Address,
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
    pub async fn new(provider: P, entrypoint: Address) -> UpstreamResult<Self> {
        let chain_id = provider.get_chain_id().await?;
        Ok(Self { chain_id, provider, entrypoint })
    }

    /// Get the address of this upstream's signer.
    pub fn default_signer_address(&self) -> Address {
        self.provider.default_signer_address()
    }

    /// Get the entrypoint on this chain.
    pub fn entrypoint(&self) -> Address {
        self.entrypoint
    }

    /// Get the code of the given account.
    pub async fn get_code(&self, address: Address) -> UpstreamResult<Bytes> {
        Ok(self.provider.get_code_at(address).await?)
    }

    /// Get token decimals from chain.
    pub async fn get_token_decimals(&self, token: Address) -> UpstreamResult<u8> {
        Ok(IERC20::new(token, &self.provider).decimals().call().await?._0)
    }

    /// Perform an `eth_call`.
    pub async fn call<C: SolCall>(
        &self,
        tx: &TransactionRequest,
    ) -> Result<C::Return, SendActionError> {
        self.provider
            .call(tx)
            .await
            .map_err(|err| SendActionError::InternalError(err.into()))
            .and_then(|r| {
                C::abi_decode_returns(&r[..], false)
                    .map_err(|err| SendActionError::InternalError(err.into()))
            })
    }

    /// Estimate gas and fees of the transaction request.
    pub async fn estimate(
        &self,
        tx: &TransactionRequest,
        overrides: &AddressMap<AccountOverride>,
    ) -> UpstreamResult<(u64, Eip1559Estimation)> {
        let (estimate, fee_estimate) = tokio::join!(
            self.provider.estimate_gas(tx).overrides(overrides),
            self.provider.estimate_eip1559_fees(None)
        );

        Ok((estimate?, fee_estimate?))
    }

    /// Sign and send the transaction request.
    pub async fn sign_and_send(&self, tx: TransactionRequest) -> UpstreamResult<TxHash> {
        Ok(self.provider.send_transaction(tx).await.map(|pending| *pending.tx_hash())?)
    }
}
