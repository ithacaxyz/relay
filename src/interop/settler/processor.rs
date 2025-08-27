use alloy::primitives::{B256, Bytes, ChainId};
use futures_util::future::try_join_all;
use std::{collections::HashSet, time::Duration};
use tracing::{debug, error, info};

use super::{
    Settler, SettlerId,
    layerzero::{EndpointId, verification::VerificationResult},
};
use crate::{
    error::StorageError,
    transactions::{RelayTransaction, interop::InteropBundle},
};

/// Errors that can occur during settlement processing.
#[derive(thiserror::Error, Debug)]
pub enum SettlementError {
    /// Storage error occurred.
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
    /// Settler ID mismatch.
    #[error("Expected settler '{expected}' but got '{got}'")]
    SettlerIdMismatch {
        /// The expected settler ID
        expected: SettlerId,
        /// The settler ID we got
        got: SettlerId,
    },
    /// Missing intent in destination transaction.
    #[error("Destination transaction missing intent")]
    MissingIntent,
    /// Unsupported chain.
    #[error("Unsupported chain: {0}")]
    UnsupportedChain(ChainId),
    /// Missing settler address for chain.
    #[error("Chain {0} has no settler address configured")]
    MissingSettlerAddress(ChainId),
    /// Unknown LayerZero endpoint ID.
    #[error("Unknown LayerZero endpoint ID: {0}")]
    UnknownEndpointId(EndpointId),
    /// RPC error.
    #[error(transparent)]
    RpcError(#[from] alloy::transports::RpcError<alloy::transports::TransportErrorKind>),
    /// Multicall error.
    #[error(transparent)]
    MulticallError(#[from] alloy::providers::MulticallError),
    /// Contract error.
    #[error(transparent)]
    ContractError(#[from] alloy::contract::Error),
    /// Abi error.
    #[error(transparent)]
    AbiError(#[from] alloy::sol_types::Error),
    /// Internal error occurred
    #[error("Internal error: {0}")]
    InternalError(String),
    /// Verification timeout
    #[error("Verification timeout for packet GUID: {0}")]
    Timeout(B256),
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
    pub fn new(settler: Box<dyn Settler>) -> Self {
        Self { settler }
    }

    /// Returns the settler ID.
    pub fn settler_id(&self) -> SettlerId {
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
    /// Returns verification result with details about successes and failures.
    pub async fn wait_for_verifications(
        &self,
        bundle: &InteropBundle,
        timeout: Duration,
    ) -> Result<VerificationResult, SettlementError> {
        self.settler.wait_for_verifications(bundle, timeout).await
    }

    /// Build execute receive transactions needed after verification.
    pub async fn build_execute_receive_transactions(
        &self,
        bundle: &InteropBundle,
    ) -> Result<Vec<RelayTransaction>, SettlementError> {
        self.settler.build_execute_receive_transactions(bundle).await
    }

    /// Validates that the bundle's settler ID matches this processor's settler.
    ///
    /// We trust that any settler address in a properly signed intent is valid.
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
                expected: self.settler.id(),
                got: bundle.settler_id,
            });
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

            let quote = dst_tx.quote().ok_or(SettlementError::MissingIntent)?;
            let result = self
                .settler
                .build_execute_send_transaction(
                    settlement_id,
                    destination_chain,
                    source_chains.clone(),
                    quote.orchestrator,
                    quote.intent.settler(),
                )
                .await?;

            if let Some(tx) = result {
                Ok::<Option<RelayTransaction>, SettlementError>(Some(tx))
            } else {
                // This might happen if the settlement was embedded with the intent execution.
                debug!(
                    bundle_id = ?bundle.id,
                    settlement_id = ?settlement_id,
                    settler_id = %self.settler.id(),
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
        interop::SimpleSettler, transactions::interop::InteropBundle, types::rpc::BundleId,
    };
    use alloy::{primitives::B256, signers::local::PrivateKeySigner};

    #[tokio::test]
    async fn test_settler_id_validation_in_build_settlements() {
        // Create a settlement processor with a simple settler
        let signer = B256::random().to_string().parse::<PrivateKeySigner>().unwrap();
        let settler = Box::new(SimpleSettler::new(signer, Default::default()));
        let processor = SettlementProcessor::new(settler);

        // Create a bundle with a different settler ID
        let bundle = InteropBundle::new(BundleId::random(), SettlerId::Test);

        // Try to build settlements - should fail due to settler mismatch
        let result = processor.build_settlements(&bundle).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            SettlementError::SettlerIdMismatch { expected, got } => {
                assert_eq!(expected, SettlerId::Simple);
                assert_eq!(got, SettlerId::Test);
            }
            _ => panic!("Expected SettlerIdMismatch error"),
        }
    }
}
