use std::marker::PhantomData;

use alloy_primitives::{Address, Bytes, TxHash};
use alloy_provider::{utils::Eip1559Estimation, Provider, WalletProvider};
use alloy_rpc_types::TransactionRequest;
use alloy_transport::Transport;

use crate::error::OdysseyWalletError;

/// A wrapper around an Alloy provider for signing and sending sponsored transactions.
#[derive(Debug)]
pub struct Upstream<P, T> {
    provider: P,
    _transport: PhantomData<T>,
}

impl<P, T> Upstream<P, T> {
    /// Create a new [`Upstream`]
    pub const fn new(provider: P) -> Self {
        Self { provider, _transport: PhantomData }
    }
}

impl<P, T> Upstream<P, T>
where
    P: Provider<T> + WalletProvider,
    T: Transport + Clone,
{
    pub fn default_signer_address(&self) -> Address {
        self.provider.default_signer_address()
    }

    pub async fn get_code(&self, address: Address) -> Result<Bytes, OdysseyWalletError> {
        self.provider
            .get_code_at(address)
            .await
            .map_err(|err| OdysseyWalletError::InternalError(err.into()))
    }

    pub async fn estimate(
        &self,
        tx: &TransactionRequest,
    ) -> Result<(u64, Eip1559Estimation), OdysseyWalletError> {
        let (estimate, fee_estimate) =
            tokio::join!(self.provider.estimate_gas(tx), self.provider.estimate_eip1559_fees(None));

        Ok((
            estimate.map_err(|err| OdysseyWalletError::InternalError(err.into()))?,
            fee_estimate.map_err(|err| OdysseyWalletError::InternalError(err.into()))?,
        ))
    }

    pub async fn sign_and_send(
        &self,
        tx: TransactionRequest,
    ) -> Result<TxHash, OdysseyWalletError> {
        self.provider
            .send_transaction(tx)
            .await
            .map_err(|err| OdysseyWalletError::InternalError(err.into()))
            .map(|pending| *pending.tx_hash())
    }
}
