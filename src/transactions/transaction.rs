use std::sync::Arc;

use crate::types::{EntryPoint, SignedQuote};
use alloy::{
    consensus::{TxEip1559, TxEip7702, TypedTransaction},
    eips::eip7702::SignedAuthorization,
    primitives::{Address, B256, Bytes, U256},
    sol_types::{SolCall, SolValue},
};

/// Transaction type used by relay.
#[derive(Debug, Clone)]
pub struct RelayTransaction {
    /// Id of the transaction.
    pub id: B256,
    /// [`UserOp`] to send.
    pub quote: SignedQuote,
    /// Destination entrypoint.
    pub entrypoint: Address,
    /// EIP-7702 [`SignedAuthorization`] to attach, if any.
    pub authorization: Option<SignedAuthorization>,
}

impl RelayTransaction {
    /// Create a new [`RelayTransaction`].
    pub fn new(
        quote: SignedQuote,
        entrypoint: Address,
        authorization: Option<SignedAuthorization>,
    ) -> Self {
        Self { id: quote.ty().digest(), quote, entrypoint, authorization }
    }

    /// Builds a [`TypedTransaction`] for this quote given a nonce.
    pub fn build(&self, nonce: u64) -> TypedTransaction {
        let input: Bytes =
            EntryPoint::executeCall { encodedUserOp: self.quote.ty().op.abi_encode().into() }
                .abi_encode()
                .into();

        // TODO: move calculations here, only store and sign neccesary values in the quote
        let gas_limit = self.quote.ty().tx_gas;
        let max_fee_per_gas = self.quote.ty().native_fee_estimate.max_fee_per_gas;
        let max_priority_fee_per_gas = self.quote.ty().native_fee_estimate.max_priority_fee_per_gas;

        if let Some(auth) = &self.authorization {
            TxEip7702 {
                authorization_list: vec![auth.clone()],
                chain_id: self.quote.ty().chain_id,
                nonce,
                to: self.entrypoint,
                input,
                gas_limit,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                value: U256::ZERO,
                access_list: Default::default(),
            }
            .into()
        } else {
            TxEip1559 {
                chain_id: self.quote.ty().chain_id,
                nonce,
                to: self.entrypoint.into(),
                input,
                gas_limit,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                value: U256::ZERO,
                access_list: Default::default(),
            }
            .into()
        }
    }
}

/// Status of a transaction.
#[derive(Clone, Debug, Default)]
pub enum TransactionStatus {
    /// Transaction is being broadcasted.
    #[default]
    InFlight,
    /// Transaction is pending.
    Pending(B256),
    /// Transaction has been confirmed.
    Confirmed(B256),
    /// Failed to broadcast the transaction.
    Failed(Arc<dyn std::error::Error + Send + Sync>),
}
