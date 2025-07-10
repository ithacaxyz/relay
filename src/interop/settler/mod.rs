/// LayerZero settler implementation.
pub mod layer_zero;
/// Settlement processor for handling cross-chain settlements.
pub mod processor;
/// Simple settler implementation for testing and development.
pub mod simple;

pub use layer_zero::LayerZeroSettler;
pub use processor::{SettlementError, SettlementProcessor, SettlementUpdate};
pub use simple::SimpleSettler;

use alloy::primitives::{Address, B256, Bytes};
use async_trait::async_trait;

use crate::transactions::RelayTransaction;

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

    /// Builds a send settlement transaction for the given parameters.
    ///
    /// This method is only called after all the destination intents are confirmed.
    async fn build_send_settlement(
        &self,
        settlement_id: B256,
        current_chain_id: u64,
        source_chains: Vec<u64>,
        settler_contract: Address,
    ) -> Result<Option<RelayTransaction>, SettlementError>;

    /// Encodes the settler-specific context for the given destination chains.
    ///
    /// For example LayerZero settler returns encoded endpoint IDs for the destination chains.
    fn encode_settler_context(
        &self,
        destination_chains: Vec<u64>,
    ) -> Result<Bytes, SettlementError>;
}
