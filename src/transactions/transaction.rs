use crate::{
    interop::EscrowDetails,
    types::{IEscrow, Quote, SignedCalls},
};
use alloy::{
    consensus::{Transaction, TxEip1559, TxEip7702, TxEnvelope, TypedTransaction},
    eips::{eip1559::Eip1559Estimation, eip7702::SignedAuthorization},
    primitives::{Address, B256, Bytes, ChainId, TxKind, U256, wrap_fixed_bytes},
    rpc::types::TransactionReceipt,
    sol_types::SolCall,
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

/// Kind of transaction we are processing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RelayTransactionKind {
    /// An intent we need to relay for a user.
    Intent {
        /// [`Intent`] to send.
        quote: Box<Quote>,
        /// EIP-7702 [`SignedAuthorization`] to attach, if any.
        authorization: Option<SignedAuthorization>,
    },
    /// An arbitrary internal relay transaction for maintenance purposes.
    Internal {
        /// Kind of the transaction.
        kind: TxKind,
        /// Input of the transaction.
        input: Bytes,
        /// Chain id of the transaction.
        chain_id: ChainId,
        /// Gas limit of the transaction.
        gas_limit: u64,
    },
}

impl RelayTransactionKind {
    /// Returns the chain id of the transaction.
    pub fn chain_id(&self) -> u64 {
        match self {
            Self::Intent { quote, .. } => quote.chain_id,
            Self::Internal { chain_id, .. } => *chain_id,
        }
    }
}

/// Transaction type used by relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayTransaction {
    /// Id of the transaction.
    pub id: TxId,
    /// Kind of the transaction.
    #[serde(flatten)]
    pub kind: RelayTransactionKind,
    /// Trace context for the transaction.
    #[serde(with = "crate::serde::trace_context", default)]
    pub trace_context: Context,
    /// Time at which we've received this transaction.
    pub received_at: DateTime<Utc>,
}

impl RelayTransaction {
    /// Create a new [`RelayTransaction`].
    pub fn new(quote: Quote, authorization: Option<SignedAuthorization>) -> Self {
        Self {
            id: TxId(B256::random()),
            kind: RelayTransactionKind::Intent { quote: Box::new(quote), authorization },
            trace_context: Context::current(),
            received_at: Utc::now(),
        }
    }

    /// Create a new [`RelayTransaction`] for an internal transaction.
    pub fn new_internal(
        kind: impl Into<TxKind>,
        input: impl Into<Bytes>,
        chain_id: ChainId,
        gas_limit: u64,
    ) -> Self {
        Self {
            id: TxId(B256::random()),
            kind: RelayTransactionKind::Internal {
                kind: kind.into(),
                input: input.into(),
                chain_id,
                gas_limit,
            },
            trace_context: Context::current(),
            received_at: Utc::now(),
        }
    }

    /// Builds a [`TypedTransaction`] for this quote given a nonce.
    pub fn build(&self, nonce: u64, fees: Eip1559Estimation) -> TypedTransaction {
        match &self.kind {
            RelayTransactionKind::Intent { quote, authorization, .. } => {
                let gas_limit = quote.tx_gas;
                let max_fee_per_gas = fees.max_fee_per_gas;
                let max_priority_fee_per_gas = fees.max_priority_fee_per_gas;

                let mut intent = quote.intent.clone();

                let payment_amount = (quote.extra_payment
                    + (U256::from(gas_limit)
                        * U256::from(fees.max_fee_per_gas)
                        * U256::from(10u128.pow(quote.payment_token_decimals as u32)))
                    .div_ceil(quote.eth_price))
                .min(intent.totalPaymentMaxAmount);

                intent.prePaymentAmount = payment_amount;
                intent.totalPaymentAmount = payment_amount;

                let input = intent.encode_execute();

                if let Some(auth) = &authorization {
                    TxEip7702 {
                        authorization_list: vec![auth.clone()],
                        chain_id: quote.chain_id,
                        nonce,
                        to: quote.orchestrator,
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
                        chain_id: quote.chain_id,
                        nonce,
                        to: quote.orchestrator.into(),
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
            RelayTransactionKind::Internal { kind, input, chain_id, gas_limit } => TxEip1559 {
                chain_id: *chain_id,
                nonce,
                to: *kind,
                input: input.clone(),
                gas_limit: *gas_limit,
                max_fee_per_gas: fees.max_fee_per_gas,
                max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
                value: U256::ZERO,
                access_list: Default::default(),
            }
            .into(),
        }
    }

    /// Returns the chain id of the transaction.
    pub fn chain_id(&self) -> u64 {
        self.kind.chain_id()
    }

    /// Returns the maximum fee we can afford for a transaction.
    pub fn max_fee_for_transaction(&self) -> u128 {
        if let RelayTransactionKind::Intent { quote, .. } = &self.kind {
            quote.native_fee_estimate.max_fee_per_gas
        } else {
            u128::MAX
        }
    }

    /// Returns the EOA of the intent.
    pub fn eoa(&self) -> Option<&Address> {
        if let RelayTransactionKind::Intent { quote, .. } = &self.kind {
            Some(&quote.intent.eoa)
        } else {
            None
        }
    }

    /// Returns the [`Quote`] of the transaction, if it's a [`RelayTransactionKind::Intent`].
    pub fn quote(&self) -> Option<&Quote> {
        if let RelayTransactionKind::Intent { quote, .. } = &self.kind { Some(quote) } else { None }
    }

    /// Whether the transaction is an intent.
    pub fn is_intent(&self) -> bool {
        matches!(self.kind, RelayTransactionKind::Intent { .. })
    }

    /// Extracts escrow details from this transaction if it contains an escrow call.
    /// This parses the transaction's last call to find escrow data, as escrow calls
    /// are always placed last in the call sequence.
    pub fn extract_escrow_details(&self) -> Option<EscrowDetails> {
        if let RelayTransactionKind::Intent { quote, .. } = &self.kind {
            // Get the chain ID from the transaction
            let chain_id = self.chain_id();

            // Look for escrow call in the intent's calls - escrow calls are always last
            if let Ok(calls) = quote.intent.calls() {
                if let Some(call) = calls.last() {
                    // Try to decode as an escrow call
                    if let Ok(escrow_call) = IEscrow::escrowCall::abi_decode(&call.data) {
                        // We found an escrow call! Extract the first escrow
                        if let Some(escrow) = escrow_call._escrows.first() {
                            // Create EscrowDetails from the escrow
                            return Some(EscrowDetails::new(
                                escrow.clone(),
                                chain_id,
                                call.to, // The escrow contract address
                            ));
                        }
                    }
                }
            }
        }
        None
    }

    /// Returns escrow IDs from a refund transaction.
    ///
    /// For refund transactions, decodes the call data to extract escrow IDs.
    /// For other transaction types, returns an empty vector.
    pub fn escrow_ids(&self) -> Vec<B256> {
        match &self.kind {
            RelayTransactionKind::Internal { input, .. } => IEscrow::refundCall::abi_decode(input)
                .map(|call| call.escrowIds)
                .unwrap_or_default(),
            _ => vec![],
        }
    }
}

/// Error occurred while processing a transaction.
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
    Confirmed(Box<TransactionReceipt>),
    /// Failed to broadcast the transaction.
    Failed(Arc<dyn TransactionFailureReason>),
}

impl TransactionStatus {
    /// Creates a new [`TransactionStatus::Failed`] status with the given reason.
    pub fn failed<R: TransactionFailureReason + 'static>(reason: R) -> Self {
        Self::Failed(Arc::new(reason))
    }

    /// Whether the status is final.
    pub fn is_final(&self) -> bool {
        matches!(self, Self::Confirmed(_) | Self::Failed(_))
    }

    /// Whether the transaction is confirmed.
    pub fn is_confirmed(&self) -> bool {
        matches!(self, Self::Confirmed(_))
    }

    /// Whether the transaction has failed.
    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed(_))
    }

    /// Whether the transaction is pending (either InFlight or Pending).
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::InFlight | Self::Pending(_))
    }

    /// The transaction hash of the transaction, if any.
    pub fn tx_hash(&self) -> Option<B256> {
        match self {
            Self::Pending(hash) => Some(*hash),
            Self::Confirmed(receipt) => Some(receipt.transaction_hash),
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
    pub sent_at: DateTime<Utc>,
}

impl PendingTransaction {
    /// Returns the chain id of the transaction.
    pub fn chain_id(&self) -> u64 {
        self.tx.chain_id()
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
