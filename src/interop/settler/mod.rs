/// LayerZero settler implementation.
pub mod layerzero;
/// Settlement processor for handling cross-chain settlements.
pub mod processor;
/// Simple settler implementation for testing and development.
pub mod simple;

pub use layerzero::{LayerZeroSettler, verification::VerificationResult};
pub use processor::{SettlementError, SettlementProcessor};
pub use simple::SimpleSettler;

use alloy::primitives::{Address, B256, Bytes};
use async_trait::async_trait;
use std::time::Duration;

use crate::transactions::{RelayTransaction, interop::InteropBundle};

/// Trait for cross-chain settlement implementations.
#[async_trait]
pub trait Settler: Send + Sync + std::fmt::Debug {
    /// Returns a unique identifier for this settler implementation.
    ///
    /// This ID is used to match bundles with their corresponding settler.
    /// Common values: "simple", "layer_zero"
    fn id(&self) -> &'static str;

    /// Returns the settler contract address.
    ///
    /// This is the address of the on-chain contract that handles settlement logic.
    fn address(&self) -> Address;

    /// Builds a execute send transaction for the given parameters.
    ///
    /// This method is only called after all the destination intents are confirmed.
    async fn build_execute_send_transaction(
        &self,
        settlement_id: B256,
        current_chain_id: u64,
        source_chains: Vec<u64>,
        orchestrator: Address,
    ) -> Result<Option<RelayTransaction>, SettlementError>;

    /// Encodes the settler-specific context for the given destination chains.
    ///
    /// For example LayerZero settler returns encoded endpoint IDs for the destination chains.
    fn encode_settler_context(
        &self,
        destination_chains: Vec<u64>,
    ) -> Result<Bytes, SettlementError>;

    /// Wait for settlement verifications with a timeout.
    ///
    /// For LayerZero, this waits for message verification on destination chains.
    /// For simple settler, this immediately returns success.
    ///
    /// Returns verification result with details about successes and failures.
    async fn wait_for_verifications(
        &self,
        bundle: &InteropBundle,
        timeout: Duration,
    ) -> Result<VerificationResult, SettlementError>;

    /// Build execute receive transactions needed after verification.
    async fn build_execute_receive_transactions(
        &self,
        bundle: &InteropBundle,
    ) -> Result<Vec<RelayTransaction>, SettlementError>;
}
