use crate::types::{EntryPoint, SignedQuote};
use alloy::{
    consensus::{Transaction, TxEip1559, TxEip7702, TxEnvelope, TypedTransaction},
    eips::{eip1559::Eip1559Estimation, eip7702::SignedAuthorization},
    primitives::{Address, B256, Bytes, U256, wrap_fixed_bytes},
    sol_types::{SolCall, SolValue},
};
use chrono::{DateTime, Utc};
use opentelemetry::Context;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

wrap_fixed_bytes! {
    /// An id of the transaction being handled by the relay.
    ///
    /// Id always corresponds to a single on-chain transaction vs a bundle of multiple transactions.
    ///
    /// Note: this is different from transaction hash, as the hash corresponding to an id might change.
    /// The [`TxId`] should never be exposed to a user, use [`crate::types::rpc::BundleId`] instead.
    pub struct TxId<32>;
}

/// Transaction type used by relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayTransaction {
    /// Id of the transaction.
    pub id: TxId,
    /// [`UserOp`] to send.
    pub quote: SignedQuote,
    /// Destination entrypoint.
    pub entrypoint: Address,
    /// EIP-7702 [`SignedAuthorization`] to attach, if any.
    pub authorization: Option<SignedAuthorization>,
    /// Trace context for the transaction.
    #[serde(with = "crate::serde::trace_context", default)]
    pub trace_context: Context,
}

impl RelayTransaction {
    /// Create a new [`RelayTransaction`].
    pub fn new(
        quote: SignedQuote,
        entrypoint: Address,
        authorization: Option<SignedAuthorization>,
    ) -> Self {
        Self {
            id: TxId(quote.ty().digest()),
            quote,
            entrypoint,
            authorization,
            trace_context: Context::current(),
        }
    }

    /// Builds a [`TypedTransaction`] for this quote given a nonce.
    pub fn build(&self, nonce: u64, fees: Eip1559Estimation) -> TypedTransaction {
        let input: Bytes =
            EntryPoint::executeCall { encodedUserOp: self.quote.ty().op.abi_encode().into() }
                .abi_encode()
                .into();

        // TODO: move calculations here, only store and sign neccesary values in the quote
        let gas_limit = self.quote.ty().tx_gas;
        let max_fee_per_gas = fees.max_fee_per_gas;
        let max_priority_fee_per_gas = fees.max_priority_fee_per_gas;

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

    /// Returns the chain id of the transaction.
    pub fn chain_id(&self) -> u64 {
        self.quote.ty().chain_id
    }

    /// Returns the maximum fee we can afford for a transaction.
    pub fn max_fee_for_transaction(&self) -> u128 {
        self.quote.ty().native_fee_estimate.max_fee_per_gas
    }
}

pub trait TransactionFailureReason: std::fmt::Display + std::fmt::Debug + Send + Sync {}
impl<T> TransactionFailureReason for T where T: std::fmt::Display + std::fmt::Debug + Send + Sync {}

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
    Failed(Arc<dyn TransactionFailureReason>),
}

impl TransactionStatus {
    /// Whether the status is final.
    pub fn is_final(&self) -> bool {
        matches!(self, Self::Confirmed(_) | Self::Failed(_))
    }

    /// The transaction hash of the transaction, if any.
    pub fn tx_hash(&self) -> Option<B256> {
        match self {
            Self::Pending(hash) | Self::Confirmed(hash) => Some(*hash),
            _ => None,
        }
    }
}

/// A [`RelayTransaction`] that has been sent to the network.
#[derive(Debug, Clone)]
pub struct PendingTransaction {
    /// The [`RelayTransaction`] that was sent.
    pub tx: RelayTransaction,
    /// All signed and sent [`TxEnvelope`]s. All transactions here are sorted by priority fee and
    /// are guaranteed to have the same nonce.
    ///
    /// This vector is guaranteed to have at least one element.
    pub sent: Vec<TxEnvelope>,
    /// Signer that signed the transaction.
    pub signer: Address,
    /// Time at which we've received this transaction.
    pub received_at: DateTime<Utc>,
}

impl PendingTransaction {
    /// Returns the chain id of the transaction.
    pub fn chain_id(&self) -> u64 {
        self.tx.quote.ty().chain_id
    }

    /// Returns the [`BundleId`] of the transaction.
    pub fn id(&self) -> TxId {
        self.tx.id
    }

    /// Returns the latest sent transaction with the highest fees.
    pub fn best_tx(&self) -> &TxEnvelope {
        self.sent.last().unwrap()
    }

    /// Returns the nonce of the transaction.
    pub fn nonce(&self) -> u64 {
        self.best_tx().nonce()
    }

    /// Returns the [`Eip1559Estimation`] of the transaction.
    pub fn fees(&self) -> Eip1559Estimation {
        Eip1559Estimation {
            max_fee_per_gas: self.best_tx().max_fee_per_gas(),
            max_priority_fee_per_gas: self.best_tx().max_priority_fee_per_gas().unwrap_or_default(),
        }
    }
}
