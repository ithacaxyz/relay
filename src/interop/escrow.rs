//! Escrow details.

use crate::types::Escrow;
use alloy::primitives::{Address, B256, ChainId};
use serde::{Deserialize, Serialize};

/// Details of an escrow including metadata for tracking
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowDetails {
    /// The underlying escrow data
    pub escrow: Escrow,
    /// Unique identifier for the escrow (computed from escrow data)
    pub escrow_id: B256,
    /// Chain ID where the escrow resides
    pub chain_id: ChainId,
    /// Address of the escrow contract
    pub escrow_address: Address,
}

impl EscrowDetails {
    /// Creates a new `EscrowDetails` from an [`Escrow`] and additional metadata.
    ///
    /// The escrow ID is automatically calculated from the escrow data using keccak256.
    pub fn new(escrow: Escrow, chain_id: ChainId, escrow_address: Address) -> Self {
        let escrow_id = escrow.calculate_id();
        Self { escrow, escrow_id, chain_id, escrow_address }
    }
}
