use alloy::primitives::{Address, Bytes, ChainId, map::HashMap};
use futures_util::future::try_join_all;
use std::collections::HashSet;
use tracing::{debug, error, info, warn};

use super::Settler;
use crate::{
    error::StorageError,
    storage::{RelayStorage, StorageApi},
    transactions::{
        RelayTransaction, TransactionServiceError, TransactionServiceHandle, TransactionStatus,
        TxId,
        interop::{BundleStatus, InteropBundle},
    },
};

/// Errors that can occur during settlement processing.
#[derive(thiserror::Error, Debug)]
pub enum SettlementError {
    /// Storage error occurred.
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
    /// Transaction service error occurred.
    #[error("Transaction service error: {0}")]
    TransactionService(#[from] TransactionServiceError),
    /// Invalid bundle state for settlement.
    #[error("Invalid bundle state for settlement: {0:?}")]
    InvalidBundleState(BundleStatus),
    /// No transaction service found for chain.
    #[error("No transaction service for chain {0}")]
    NoTransactionService(ChainId),
    /// Settler ID mismatch.
    #[error("Bundle settler '{bundle_settler}' does not match current settler '{current_settler}'")]
    SettlerIdMismatch {
        /// The settler ID from the bundle
        bundle_settler: String,
        /// The current settler ID
        current_settler: &'static str,
    },
    /// Settler address mismatch.
    #[error(
        "Transaction {tx_id} has settler '{intent_settler}' but current settler is '{current_settler}'"
    )]
    SettlerAddressMismatch {
        /// The transaction ID with the mismatch
        tx_id: TxId,
        /// The settler address from the intent
        intent_settler: Address,
        /// The current settler address
        current_settler: Address,
    },
    /// Missing intent in destination transaction.
    #[error("Destination transaction missing intent")]
    MissingIntent,
    /// Unsupported chain.
    #[error("Unsupported chain: {0}")]
    UnsupportedChain(ChainId),
    /// RPC error from provider calls.
    #[error("RPC error: {0}")]
    RpcError(#[from] alloy::transports::RpcError<alloy::transports::TransportErrorKind>),
    /// Multicall error.
    #[error("Multicall error: {0}")]
    MulticallError(#[from] alloy::providers::MulticallError),
}

/// Processor for handling settlement transactions in cross-chain bundles.
#[derive(Debug)]
pub struct SettlementProcessor {
    /// Storage backend for persisting data.
    storage: RelayStorage,
    /// Chain ID to transaction service mapping.
    transaction_services: HashMap<ChainId, TransactionServiceHandle>,
    /// Settler implementation for cross-chain messaging.
    settler: Box<dyn Settler>,
}

/// Update result from settlement processing.
#[derive(Debug)]
pub struct SettlementUpdate {
    /// New settlement transactions created.
    pub new_settlement_txs: Vec<RelayTransaction>,
    /// IDs of failed transactions.
    pub failed_tx_ids: Vec<TxId>,
    /// New bundle status to apply.
    pub new_status: Option<BundleStatus>,
}

impl SettlementProcessor {
    /// Creates a new settlement processor.
    ///
    /// # Arguments
    ///
    /// * `storage` - The relay storage instance
    /// * `transaction_services` - Map of chain IDs to transaction service handles
    /// * `settler` - The settler implementation to use for settlements
    pub fn new(
        storage: RelayStorage,
        transaction_services: HashMap<ChainId, TransactionServiceHandle>,
        settler: Box<dyn Settler>,
    ) -> Self {
        Self { storage, transaction_services, settler }
    }

    /// Returns the settler address.
    pub fn settler_address(&self) -> Address {
        self.settler.address()
    }

    /// Returns the settler ID.
    pub fn settler_id(&self) -> &'static str {
        self.settler.id()
    }

    /// Encodes the settler context for the given destination chains.
    pub fn encode_settler_context(
        &self,
        destination_chains: Vec<ChainId>,
    ) -> Result<Bytes, SettlementError> {
        self.settler.encode_settler_context(destination_chains)
    }

    /// Validates that the bundle's settler ID matches this processor's settler and that
    /// all destination transactions have the correct settler address.
    fn validate_settler(&self, bundle: &InteropBundle) -> Result<(), SettlementError> {
        // Validate bundle settler ID
        if bundle.settler_id != self.settler.id() {
            error!(
                bundle_id = ?bundle.id,
                bundle_settler = %bundle.settler_id,
                current_settler = %self.settler.id(),
                "Bundle settler ID does not match current settler"
            );
            return Err(SettlementError::SettlerIdMismatch {
                bundle_settler: bundle.settler_id.clone(),
                current_settler: self.settler.id(),
            });
        }

        // Validate settler address in all destination transactions
        let settler_address = self.settler.address();
        for dst_tx in &bundle.dst_txs {
            if let Some(quote) = dst_tx.quote() {
                if quote.intent.settler != settler_address {
                    error!(
                        bundle_id = ?bundle.id,
                        tx_id = ?dst_tx.id,
                        intent_settler = %quote.intent.settler,
                        current_settler = %settler_address,
                        "Destination transaction has incorrect settler address"
                    );
                    return Err(SettlementError::SettlerAddressMismatch {
                        tx_id: dst_tx.id,
                        intent_settler: quote.intent.settler,
                        current_settler: settler_address,
                    });
                }
            }
        }

        Ok(())
    }

    /// Queues send settlement transactions for a bundle and sends them.
    pub async fn queue_send_settlements(
        &self,
        bundle: &InteropBundle,
    ) -> Result<SettlementUpdate, SettlementError> {
        info!(bundle_id = ?bundle.id, "Queuing send settlements for bundle");

        // Validate that the bundle's settler matches this settler
        self.validate_settler(bundle)?;

        debug!(
            bundle_id = ?bundle.id,
            num_destinations = bundle.dst_txs.len(),
            num_sources = bundle.src_txs.len(),
            "Building settlement transactions - one per destination"
        );

        // Validate that we have transaction services for all destination chains upfront
        for dst_tx in &bundle.dst_txs {
            if !self.transaction_services.contains_key(&dst_tx.chain_id()) {
                return Err(SettlementError::NoTransactionService(dst_tx.chain_id()));
            }
        }

        // Get all unique source chain IDs
        let mut source_chain_set = HashSet::with_capacity(bundle.src_txs.len());
        for tx in &bundle.src_txs {
            source_chain_set.insert(tx.chain_id());
        }
        let source_chains: Vec<ChainId> = source_chain_set.into_iter().collect();

        // Build settlement transactions
        let settlement_results = try_join_all(bundle.dst_txs.iter().map(async |dst_tx| {
            let settlement_id = dst_tx.eip712_digest().ok_or(SettlementError::MissingIntent)?;
            let destination_chain = dst_tx.chain_id();

            info!(
                bundle_id = ?bundle.id,
                settlement_id = ?settlement_id,
                destination_chain = destination_chain,
                source_chains = ?source_chains,
                "Building settlement transaction for destination"
            );

            let orchestrator = dst_tx.quote().ok_or(SettlementError::MissingIntent)?.orchestrator;
            let result = self
                .settler
                .build_send_settlement(
                    settlement_id,
                    destination_chain,
                    source_chains.clone(),
                    orchestrator,
                )
                .await?;

            if let Some(tx) = result {
                Ok::<Option<RelayTransaction>, SettlementError>(Some(tx))
            } else {
                // This might happen if the settlement was embedded with the intent execution.
                debug!(
                    bundle_id = ?bundle.id,
                    settlement_id = ?settlement_id,
                    settler_id = self.settler.id(),
                    "Settler did not produce a send settlement transaction"
                );
                Ok(None)
            }
        }))
        .await?;

        // Collect successful settlement transactions
        let settlement_txs: Vec<RelayTransaction> =
            settlement_results.into_iter().flatten().collect();

        // Create a new bundle with settlement transactions
        let mut updated_bundle = bundle.clone();
        updated_bundle.settlement_txs = settlement_txs;

        // Queue the settlement transactions atomically
        self.storage
            .update_bundle_and_queue_transactions(
                &updated_bundle,
                BundleStatus::SettlementsQueued,
                &updated_bundle.settlement_txs,
            )
            .await?;

        // Send the settlement transactions
        for tx in &updated_bundle.settlement_txs {
            debug!(tx_id = ?tx.id, chain_id = tx.chain_id(), "Sending settlement transaction");

            self.transaction_services
                .get(&tx.chain_id())
                .expect("transaction service should exist")
                .send_transaction_no_queue(tx.clone());
        }

        info!(
            bundle_id = ?bundle.id,
            num_settlements = updated_bundle.settlement_txs.len(),
            "Settlement transactions queued and sent"
        );

        Ok(SettlementUpdate {
            new_settlement_txs: updated_bundle.settlement_txs,
            failed_tx_ids: vec![],
            new_status: Some(BundleStatus::SettlementsQueued),
        })
    }

    /// Monitors settlement transaction completion and returns failed transaction IDs.
    pub async fn monitor_settlement_completion(
        &self,
        bundle: &InteropBundle,
    ) -> Result<Vec<TxId>, SettlementError> {
        info!(
            bundle_id = ?bundle.id,
            num_settlements = bundle.settlement_txs.len(),
            "Monitoring settlement transaction completion"
        );

        // Wait for all settlement transactions to complete
        let results = try_join_all(bundle.settlement_txs.iter().map(async |tx| {
            let tx_service = self
                .transaction_services
                .get(&tx.chain_id())
                .ok_or_else(|| SettlementError::NoTransactionService(tx.chain_id()))?;

            let status = tx_service.wait_for_tx(tx.id).await?;
            Ok::<_, SettlementError>((tx.id, status))
        }))
        .await?;

        // Process results and collect failed transaction IDs
        let failed_ids = results
            .into_iter()
            .filter_map(|(tx_id, status)| match status {
                TransactionStatus::Confirmed(_) => {
                    info!(tx_id = ?tx_id, "Settlement transaction confirmed");
                    None
                }
                TransactionStatus::Failed(e) => {
                    warn!(tx_id = ?tx_id, error = %e, "Settlement transaction failed");
                    Some(tx_id)
                }
                _ => unreachable!("wait_for_tx only returns finalized statuses"),
            })
            .collect();

        Ok(failed_ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        interop::SimpleSettler, storage::RelayStorage, transactions::interop::InteropBundle,
        types::rpc::BundleId,
    };
    use alloy::primitives::{Address, ChainId};

    #[tokio::test]
    async fn test_settler_id_validation_in_queue_settlements() {
        // Create a settlement processor with a simple settler
        let storage = RelayStorage::in_memory();
        let tx_services: alloy::primitives::map::HashMap<ChainId, TransactionServiceHandle> =
            Default::default();
        let settler = Box::new(SimpleSettler::new(Address::ZERO));
        let processor = SettlementProcessor::new(storage, tx_services, settler);

        // Create a bundle with a different settler ID
        let bundle = InteropBundle::new(BundleId::random(), "different_settler".to_string());

        // Try to queue settlements - should fail due to settler mismatch
        let result = processor.queue_send_settlements(&bundle).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            SettlementError::SettlerIdMismatch { bundle_settler, current_settler } => {
                assert_eq!(bundle_settler, "different_settler");
                assert_eq!(current_settler, "simple");
            }
            _ => panic!("Expected SettlerIdMismatch error"),
        }
    }
}
