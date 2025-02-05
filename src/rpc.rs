//! # Odyssey wallet.
//!
//! Implementations of a custom `wallet_` namespace for Odyssey experiment 1.
//!
//! - `odyssey_sendTransaction` that can perform service-sponsored [EIP-7702][eip-7702] delegations
//!   and send other service-sponsored transactions on behalf of EOAs with delegated code.
//!
//! # Restrictions
//!
//! `odyssey_sendTransaction` has additional verifications in place to prevent some
//! rudimentary abuse of the service's funds. For example, transactions cannot contain any
//! `value`.
//!
//! [eip-5792]: https://eips.ethereum.org/EIPS/eip-5792
//! [eip-7702]: https://eips.ethereum.org/EIPS/eip-7702

use alloy::{
    primitives::{Address, ChainId, TxHash, TxKind, U256},
    providers::{Provider, WalletProvider},
    rpc::types::TransactionRequest,
};
use jsonrpsee::{
    core::{async_trait, RpcResult},
    proc_macros::rpc,
};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{trace, warn};

use crate::{error::OdysseyWalletError, upstream::Upstream};

/// Odyssey `wallet_` RPC namespace.
#[cfg_attr(not(test), rpc(server, namespace = "wallet"))]
#[cfg_attr(test, rpc(server, client, namespace = "wallet"))]
pub trait OdysseyWalletApi {
    /// Send a sponsored transaction.
    ///
    /// The transaction will only be processed if:
    ///
    /// - The transaction is an [EIP-7702][eip-7702] transaction.
    /// - The transaction is an [EIP-1559][eip-1559] transaction to an EOA that is currently
    ///   delegated to one of the addresses above
    /// - The value in the transaction is exactly 0.
    ///
    /// The service will sign the transaction and inject it into the transaction pool, provided it
    /// is valid. The nonce is managed by the service.
    ///
    /// [eip-7702]: https://eips.ethereum.org/EIPS/eip-7702
    /// [eip-1559]: https://eips.ethereum.org/EIPS/eip-1559
    #[method(name = "sendTransaction", aliases = ["odyssey_sendTransaction"])]
    async fn send_transaction(&self, request: TransactionRequest) -> RpcResult<TxHash>;
}

/// Implementation of the Odyssey `wallet_` namespace.
#[derive(Debug)]
pub struct OdysseyWallet<P> {
    inner: Arc<OdysseyWalletInner<P>>,
}

impl<P> OdysseyWallet<P> {
    /// Create a new Odyssey wallet module.
    pub fn new(upstream: Upstream<P>, chain_id: ChainId) -> Self {
        let inner = OdysseyWalletInner { upstream, chain_id, permit: Default::default() };
        Self { inner: Arc::new(inner) }
    }

    fn chain_id(&self) -> ChainId {
        self.inner.chain_id
    }
}

#[async_trait]
impl<P> OdysseyWalletApiServer for OdysseyWallet<P>
where
    P: Provider + WalletProvider + 'static,
{
    async fn send_transaction(&self, mut request: TransactionRequest) -> RpcResult<TxHash> {
        trace!(target: "rpc::wallet", ?request, "Serving odyssey_sendTransaction");

        // validate fields common to eip-7702 and eip-1559
        validate_tx_request(&request)?;

        // validate destination
        match (request.authorization_list.is_some(), request.to) {
            // if this is an eip-1559 tx, ensure that it is an account that delegates to a
            // whitelisted address
            (false, Some(TxKind::Call(addr))) => {
                let code = self.inner.upstream.get_code(addr).await?;
                match code.as_ref() {
                    // A valid EIP-7702 delegation
                    [0xef, 0x01, 0x00, address @ ..] => {
                        let addr = Address::from_slice(address);
                        // the delegation was cleared
                        if addr.is_zero() {
                            return Err(OdysseyWalletError::IllegalDestination.into());
                        }
                    }
                    // Not an EIP-7702 delegation, or an empty (cleared) delegation
                    _ => {
                        return Err(OdysseyWalletError::IllegalDestination.into());
                    }
                }
            }
            // if it's an eip-7702 tx, let it through
            (true, _) => (),
            // create tx's disallowed
            _ => {
                return Err(OdysseyWalletError::IllegalDestination.into());
            }
        }

        // we acquire the permit here so that all following operations are performed exclusively
        let _permit = self.inner.permit.lock().await;

        // set chain id
        request.chain_id = Some(self.chain_id());

        // set gas limit
        // note: we also set the `from` field here to correctly estimate for contracts that use e.g.
        // `tx.origin`
        request.from = Some(self.inner.upstream.default_signer_address());
        let (estimate, fee_estimate) = self.inner.upstream.estimate(&request).await?;
        if estimate >= 1_000_000 {
            return Err(OdysseyWalletError::GasEstimateTooHigh { estimate }.into());
        }
        request.gas = Some(estimate);

        // set gas price
        request.max_fee_per_gas = Some(fee_estimate.max_fee_per_gas);
        request.max_priority_fee_per_gas = Some(fee_estimate.max_priority_fee_per_gas);
        request.gas_price = None;

        Ok(self.inner.upstream.sign_and_send(request).await.inspect_err(
            |err| warn!(target: "rpc::wallet", ?err, "Error adding sponsored tx to pool"),
        )?)
    }
}

/// Implementation of the Odyssey `wallet_` namespace.
#[derive(Debug)]
struct OdysseyWalletInner<P> {
    upstream: Upstream<P>,
    chain_id: ChainId,
    /// Used to guard tx signing
    permit: Mutex<()>,
}

fn validate_tx_request(request: &TransactionRequest) -> Result<(), OdysseyWalletError> {
    // reject transactions that have a non-zero value to prevent draining the service.
    if request.value.is_some_and(|val| val > U256::ZERO) {
        return Err(OdysseyWalletError::ValueNotZero);
    }

    // reject transactions that have from set, as this will be the service.
    if request.from.is_some() {
        return Err(OdysseyWalletError::FromSet);
    }

    // reject transaction requests that have nonce set, as this is managed by the service.
    if request.nonce.is_some() {
        return Err(OdysseyWalletError::NonceSet);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_tx_request, OdysseyWalletError};
    use alloy::{
        primitives::{Address, U256},
        rpc::types::TransactionRequest,
    };

    #[test]
    fn no_value_allowed() {
        assert!(matches!(
            validate_tx_request(&TransactionRequest::default().value(U256::from(1))),
            Err(OdysseyWalletError::ValueNotZero)
        ));

        assert!(matches!(
            validate_tx_request(&TransactionRequest::default().value(U256::from(0))),
            Ok(())
        ));
    }

    #[test]
    fn no_from_allowed() {
        assert!(matches!(
            validate_tx_request(&TransactionRequest::default().from(Address::ZERO)),
            Err(OdysseyWalletError::FromSet)
        ));

        assert!(matches!(validate_tx_request(&TransactionRequest::default()), Ok(())));
    }

    #[test]
    fn no_nonce_allowed() {
        assert!(matches!(
            validate_tx_request(&TransactionRequest::default().nonce(1)),
            Err(OdysseyWalletError::NonceSet)
        ));

        assert!(matches!(validate_tx_request(&TransactionRequest::default()), Ok(())));
    }
}
