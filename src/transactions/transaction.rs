use crate::types::{EntryPoint, SignedQuote};
use alloy::{
    consensus::{TxEip1559, TxEip7702, TxEnvelope, TypedTransaction},
    eips::eip7702::SignedAuthorization,
    primitives::{Address, B256, Bytes, U256, wrap_fixed_bytes},
    sol_types::{SolCall, SolValue},
};
use chrono::{DateTime, Utc};
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
}

impl RelayTransaction {
    /// Create a new [`RelayTransaction`].
    pub fn new(
        quote: SignedQuote,
        entrypoint: Address,
        authorization: Option<SignedAuthorization>,
    ) -> Self {
        Self { id: TxId(quote.ty().digest()), quote, entrypoint, authorization }
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

impl TransactionStatus {
    /// Whether the status is final.
    pub fn is_final(&self) -> bool {
        matches!(self, Self::Confirmed(_) | Self::Failed(_))
    }
}

/// A [`RelayTransaction`] that has been sent to the network.
#[derive(Debug, Clone)]
pub struct PendingTransaction {
    /// The [`RelayTransaction`] that was sent.
    pub tx: RelayTransaction,
    /// Signed [`TxEnvelope`].
    pub sent: TxEnvelope,
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

    /// Returns the hash of the transaction.
    pub fn tx_hash(&self) -> B256 {
        *self.sent.tx_hash()
    }
}
