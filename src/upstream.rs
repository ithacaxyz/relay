use alloy::{
    primitives::{map::AddressMap, Address, Bytes, ChainId, TxHash},
    providers::{utils::Eip1559Estimation, Provider, WalletProvider},
    rpc::types::{state::AccountOverride, TransactionRequest},
    sol_types::SolCall,
};

use crate::error::SendActionError;

/// A wrapper around an Alloy provider for signing and sending sponsored transactions.
#[derive(Clone, Debug)]
pub struct Upstream<P> {
    provider: P,
    entrypoint: Address,
}

impl<P> Upstream<P> {
    /// Create a new [`Upstream`]
    pub const fn new(provider: P, entrypoint: Address) -> Self {
        Self { provider, entrypoint }
    }
}

impl<P> Upstream<P>
where
    P: Provider + WalletProvider,
{
    pub fn default_signer_address(&self) -> Address {
        self.provider.default_signer_address()
    }

    pub async fn chain_id(&self) -> Result<ChainId, SendActionError> {
        self.provider.get_chain_id().await.map_err(|err| SendActionError::InternalError(err.into()))
    }

    pub fn entrypoint(&self) -> Address {
        self.entrypoint
    }

    pub async fn get_code(&self, address: Address) -> Result<Bytes, SendActionError> {
        self.provider
            .get_code_at(address)
            .await
            .map_err(|err| SendActionError::InternalError(err.into()))
    }

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

    pub async fn estimate(
        &self,
        tx: &TransactionRequest,
        overrides: &AddressMap<AccountOverride>,
    ) -> Result<(u64, Eip1559Estimation), SendActionError> {
        let (estimate, fee_estimate) = tokio::join!(
            self.provider.estimate_gas(tx).overrides(overrides),
            self.provider.estimate_eip1559_fees(None)
        );

        Ok((
            estimate.map_err(|err| SendActionError::InternalError(err.into()))?,
            fee_estimate.map_err(|err| SendActionError::InternalError(err.into()))?,
        ))
    }

    pub async fn sign_and_send(&self, tx: TransactionRequest) -> Result<TxHash, SendActionError> {
        self.provider
            .send_transaction(tx)
            .await
            .map_err(|err| SendActionError::InternalError(err.into()))
            .map(|pending| *pending.tx_hash())
    }
}
