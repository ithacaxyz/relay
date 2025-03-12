use super::transaction::{PendingTransaction, RelayTransaction, SentTransaction};
use crate::{
    signers::DynSigner,
    types::{ENTRYPOINT_NO_ERROR, EntryPoint},
};
use alloy::{
    consensus::TypedTransaction,
    network::{Ethereum, EthereumWallet, NetworkWallet},
    primitives::{Address, Bytes},
    providers::{DynProvider, PendingTransactionError, Provider},
    rpc::types::TransactionRequest,
    sol_types::SolCall,
    transports::{RpcError, TransportErrorKind, TransportResult},
};
use futures_util::lock::Mutex;
use std::sync::Arc;

/// Errors that may occur while sending a transaction.
#[derive(Debug, thiserror::Error)]
pub enum SendTxErrorKind {
    /// The userop reverted when trying transaction.
    #[error("op reverted: {revert_reason}")]
    OpRevert {
        /// The error code returned by the entrypoint.
        revert_reason: Bytes,
    },

    /// Error occurred while signing transaction.
    #[error(transparent)]
    Sign(#[from] alloy::signers::Error),

    /// RPC error.
    #[error(transparent)]
    Rpc(#[from] RpcError<TransportErrorKind>),

    /// Other errors.
    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl From<PendingTransactionError> for SendTxErrorKind {
    fn from(value: PendingTransactionError) -> Self {
        match value {
            PendingTransactionError::TransportError(err) => Self::Rpc(err),
            err => Self::Other(Box::new(err)),
        }
    }
}

/// Error returned when we fail to send a transaction.
#[derive(Debug, thiserror::Error)]
#[error("failed to send transaction: {kind}")]
pub struct SendTxError {
    /// Error kind.
    #[source]
    pub kind: SendTxErrorKind,
    /// Transaction that we failed to send.
    pub tx: RelayTransaction,
    /// Nonce chosen for the transaction, if any.
    pub nonce: Option<u64>,
}

/// A signer responsible for signing and sending transactions on a single network.
#[derive(Debug, Clone)]
pub struct Signer {
    /// Provider used by the signer.
    provider: DynProvider,
    /// Inner [`EthereumWallet`] used to sign transactions.
    wallet: EthereumWallet,
    /// Nonce of thes signer.
    nonce: Arc<Mutex<u64>>,
}

impl Signer {
    /// Creates a new [`Signer`].
    pub async fn new(provider: DynProvider, signer: DynSigner) -> TransportResult<Self> {
        let address = signer.address();
        let wallet = EthereumWallet::new(signer.0);
        let nonce = provider.get_transaction_count(address).pending().await?;

        Ok(Self { provider, wallet, nonce: Arc::new(Mutex::new(nonce)) })
    }

    /// Returns the signer address.
    pub fn address(&self) -> Address {
        NetworkWallet::<Ethereum>::default_signer_address(&self.wallet)
    }

    /// Broadcasts a given transaction.
    async fn broadcast_transaction(
        &self,
        tx: TypedTransaction,
    ) -> Result<alloy::providers::PendingTransaction, SendTxErrorKind> {
        // Sign the transaction.
        let signed =
            NetworkWallet::<Ethereum>::sign_transaction_from(&self.wallet, self.address(), tx)
                .await?;

        Ok(self.provider.send_tx_envelope(signed).await?.register().await?)
    }

    /// Signs and sends a transaction.
    pub async fn send_transaction(
        &self,
        mut tx: RelayTransaction,
    ) -> Result<PendingTransaction, SendTxError> {
        // St payment recipient to us
        tx.quote.ty_mut().op.paymentRecipient = self.address();

        let mut request: TransactionRequest = tx.build(0).into();
        // Unset nonce to avoid race condition.
        request.nonce = None;

        // Try eth_call before committing to send the actual transaction
        if let Err(kind) = self
            .provider
            .call(request)
            .await
            .and_then(|res| {
                EntryPoint::executeCall::abi_decode_returns(&res, true)
                    .map_err(TransportErrorKind::custom)
            })
            .map_err(SendTxErrorKind::from)
            .and_then(|result| {
                if result.err != ENTRYPOINT_NO_ERROR {
                    return Err(SendTxErrorKind::OpRevert { revert_reason: result.err.into() });
                }
                Ok(())
            })
        {
            return Err(SendTxError { kind, tx, nonce: None });
        }

        // Choose nonce for the transaction.
        let nonce = {
            let mut nonce = self.nonce.lock().await;
            let current_nonce = *nonce;
            *nonce += 1;
            current_nonce
        };

        // Sign and send the transaction.
        match self.broadcast_transaction(tx.build(nonce)).await {
            Ok(handle) => Ok(PendingTransaction {
                tx: SentTransaction { tx, nonce, tx_hash: *handle.tx_hash() },
                handle,
            }),
            Err(kind) => Err(SendTxError { kind, tx, nonce: Some(nonce) }),
        }
    }
}
