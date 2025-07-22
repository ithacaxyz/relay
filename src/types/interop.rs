use crate::{storage::BundleStatus, transactions::RelayTransaction};

/// Represents a batch of transactions at different stages of the interop bundle lifecycle.
#[derive(Debug)]
pub enum InteropTransactionBatch<'a> {
    /// Source chain transactions
    Source(&'a [RelayTransaction]),
    /// Destination chain transactions
    Destination(&'a [RelayTransaction]),
    /// Settlement transactions (after destination confirmation)
    ExecuteSend(&'a [RelayTransaction]),
    /// Execute receive transactions (e.g., LayerZero delivery)
    ExecuteReceive(&'a [RelayTransaction]),
    /// Refund transactions (when source/destination fails)
    Refund(&'a [RelayTransaction]),
}

impl<'a> InteropTransactionBatch<'a> {
    /// Returns the inner transactions.
    pub fn transactions(&self) -> &[RelayTransaction] {
        match self {
            Self::Source(txs) => txs,
            Self::Destination(txs) => txs,
            Self::ExecuteSend(txs) => txs,
            Self::ExecuteReceive(txs) => txs,
            Self::Refund(txs) => txs,
        }
    }

    /// Returns the appropriate queued status for this transaction batch type.
    pub fn next_status(&self) -> BundleStatus {
        match self {
            Self::Source(_) => BundleStatus::SourceQueued,
            Self::Destination(_) => BundleStatus::DestinationQueued,
            Self::ExecuteSend(_) => BundleStatus::SettlementsQueued,
            Self::ExecuteReceive(_) => BundleStatus::SettlementCompletionQueued,
            Self::Refund(_) => BundleStatus::RefundsQueued,
        }
    }

    /// Returns true if this is a settlement-related transaction batch.
    pub fn is_settlement(&self) -> bool {
        matches!(self, Self::ExecuteSend(_) | Self::ExecuteReceive(_) | Self::Refund(_))
    }
}
