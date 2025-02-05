use alloy::{
    primitives::{Address, Bytes, TxHash},
    providers::{utils::Eip1559Estimation, Provider, WalletProvider},
    rpc::types::TransactionRequest,
};

use crate::error::OdysseyWalletError;

/// A wrapper around an Alloy provider for signing and sending sponsored transactions.
#[derive(Debug, Clone)]
pub struct Upstream<P> {
    provider: P,
}

impl<P> Upstream<P> {
    /// Create a new [`Upstream`]
    pub const fn new(provider: P) -> Self {
        Self { provider }
    }
}

impl<P> Upstream<P>
where
    P: Provider + WalletProvider,
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
