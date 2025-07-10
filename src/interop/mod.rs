//! Cross-chain interoperability module.
//!
//! This module provides functionality for handling cross-chain transactions
//! and escrow management for the relay service.

pub mod escrow;
pub mod refund;
/// Settlement functionality for cross-chain bundles.
pub mod settler;

pub use escrow::EscrowDetails;
pub use refund::{RefundMonitorService, RefundProcessor, RefundProcessorError, RefundUpdate};
pub use settler::{
    LayerZeroSettler, SettlementProcessor, SettlementProcessorError, SettlementUpdate, Settler,
    SimpleSettler,
};
