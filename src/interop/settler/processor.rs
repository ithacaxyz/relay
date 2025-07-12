use alloy::primitives::{Address, Bytes, ChainId, map::HashMap};
use futures_util::future::try_join_all;
use std::{collections::HashSet, time::Duration};
use tracing::{debug, error, info};

use super::Settler;
use crate::{
    error::StorageError,
    storage::RelayStorage,
    transactions::{
        RelayTransaction, TransactionServiceError, TransactionServiceHandle, TxId,
        interop::InteropBundle,
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
    InvalidBundleState(crate::transactions::interop::BundleStatus),
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
    /// Unknown LayerZero endpoint ID.
    #[error("Unknown LayerZero endpoint ID: {0}")]
    UnknownEndpointId(u32),
    /// Unexpected transaction state.
    #[error("Unexpected transaction state: expected {expected}, but got {actual}")]
    UnexpectedTransactionState {
        /// The expected transaction state
        expected: &'static str,
        /// The actual transaction state
        actual: String,
    },
    /// Generic error.
    #[error("Error: {0}")]
    GenericError(String),
    /// Contract call error.
    #[error("Contract call failed: {0}")]
    ContractCallError(String),
    /// RPC error.
    #[error("RPC error: {0}")]
    RpcError(#[from] alloy::transports::RpcError<alloy::transports::TransportErrorKind>),
    /// Multicall error.
    #[error("Multicall error: {0}")]
    MulticallError(#[from] alloy::providers::MulticallError),
    /// No settlement transactions in bundle
    #[error("No settlement transactions in bundle")]
    NoSettlementTransactions,
    /// Failed to extract LayerZero packet info
    #[error("Failed to extract LayerZero packet info: {0}")]
    PacketExtractionError(String),
    /// LayerZero verification timeout
    #[error("LayerZero verification timeout after {0} seconds")]
    VerificationTimeout(u64),
    /// Failed to build delivery transaction
    #[error("Failed to build delivery transaction: {0}")]
    DeliveryBuildError(String),
}

/// Processor for handling settlement transactions in cross-chain bundles.
#[derive(Debug)]
pub struct SettlementProcessor {
    /// Settler implementation for cross-chain messaging.
    settler: Box<dyn Settler>,
}

impl SettlementProcessor {
    /// Creates a new settlement processor.
    ///
    /// # Arguments
    ///
    /// * `storage` - The relay storage instance (unused but kept for API compatibility)
    /// * `transaction_services` - Map of chain IDs to transaction service handles (unused but kept
    ///   for API compatibility)
    /// * `settler` - The settler implementation to use for settlements
    pub fn new(
        _storage: RelayStorage,
        _transaction_services: HashMap<ChainId, TransactionServiceHandle>,
        settler: Box<dyn Settler>,
    ) -> Self {
        Self { settler }
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

    /// Wait for settlement verifications with a timeout.
    ///
    /// Returns true if verification succeeded, false otherwise.
    pub async fn wait_for_verifications(
        &self,
        bundle: &InteropBundle,
        timeout: Duration,
    ) -> Result<bool, SettlementError> {
        self.settler.wait_for_verifications(bundle, timeout).await
    }

    /// Build execute receive transactions needed after verification.
    pub async fn build_execute_receive_transactions(
        &self,
        bundle: &InteropBundle,
    ) -> Result<Vec<RelayTransaction>, SettlementError> {
        self.settler.build_execute_receive_transactions(bundle).await
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

    /// Builds settlement transactions for a bundle.
    pub async fn build_settlements(
        &self,
        bundle: &InteropBundle,
    ) -> Result<Vec<RelayTransaction>, SettlementError> {
        info!(bundle_id = ?bundle.id, "Building settlements for bundle");

        // Validate that the bundle's settler matches this settler
        self.validate_settler(bundle)?;

        debug!(
            bundle_id = ?bundle.id,
            num_destinations = bundle.dst_txs.len(),
            num_sources = bundle.src_txs.len(),
            "Building settlement transactions - one per destination"
        );

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
                .build_execute_send_transaction(
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

        info!(
            bundle_id = ?bundle.id,
            num_settlements = settlement_txs.len(),
            "Built settlement transactions"
        );

        Ok(settlement_txs)
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
    async fn test_settler_id_validation_in_build_settlements() {
        // Create a settlement processor with a simple settler
        let storage = RelayStorage::in_memory();
        let tx_services: alloy::primitives::map::HashMap<ChainId, TransactionServiceHandle> =
            Default::default();
        let settler = Box::new(SimpleSettler::new(Address::ZERO));
        let processor = SettlementProcessor::new(storage, tx_services, settler);

        // Create a bundle with a different settler ID
        let bundle = InteropBundle::new(BundleId::random(), "different_settler".to_string());

        // Try to build settlements - should fail due to settler mismatch
        let result = processor.build_settlements(&bundle).await;

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
