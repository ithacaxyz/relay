//! Cross-chain interoperability module.
//!
//! This module provides functionality for handling cross-chain transactions
//! and escrow management for the relay service.

pub mod escrow;
pub mod refund;
/// Settlement functionality for cross-chain bundles.
pub mod settler;

use crate::{
    storage::{BundleStatus, InteropBundle},
    transactions::RelayTransaction,
};
pub use escrow::EscrowDetails;
pub use refund::{RefundMonitorService, RefundProcessor, RefundProcessorError};
pub use settler::{LayerZeroSettler, SettlementError, SettlementProcessor, Settler, SimpleSettler};

/// Types of transactions that can be queued and sent for a bundle.
#[derive(Debug, Clone)]
pub enum SettlementTransactions<'a> {
    /// Settlement transactions (after destination confirmation).
    ExecuteSend(&'a [RelayTransaction]),
    /// Execute receive transactions (e.g., LayerZero delivery).
    ExecuteReceive(&'a [RelayTransaction]),
    /// Refund transactions (when source/destination fails).
    Refund(&'a [RelayTransaction]),
}

impl<'a> SettlementTransactions<'a> {
    /// Returns the inner transactions.
    pub fn transactions(&self) -> &[RelayTransaction] {
        match self {
            Self::ExecuteSend(txs) => txs,
            Self::ExecuteReceive(txs) => txs,
            Self::Refund(txs) => txs,
        }
    }

    /// Returns the appropriate next status for this transaction type.
    pub fn next_status(&self) -> BundleStatus {
        match self {
            Self::ExecuteSend(_) => BundleStatus::SettlementsQueued,
            Self::ExecuteReceive(_) => BundleStatus::ExecuteReceiveQueued,
            Self::Refund(_) => BundleStatus::RefundsQueued,
        }
    }

    /// Adds transactions to the appropriate field in the bundle.
    pub fn add_to_bundle(&self, bundle: &mut InteropBundle) {
        match self {
            Self::ExecuteSend(txs) => {
                bundle.settlement_txs.extend_from_slice(txs);
            }
            Self::ExecuteReceive(txs) => {
                bundle.execute_receive_txs.extend_from_slice(txs);
            }
            Self::Refund(txs) => {
                bundle.refund_txs.extend_from_slice(txs);
            }
        }
    }
}
