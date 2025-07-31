//! LayerZero specific types

use crate::transactions::TxId;
use alloy::primitives::ChainId;
use serde::{Deserialize, Serialize};

/// Storage record of the latest LayerZero nonce for a specific chain and endpoint.
///
/// This struct tracks the highest nonce that has been queued for processing
/// along with the associated transaction ID. This is used for crash recovery
/// and determining the starting point for new batches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerZeroNonceRecord {
    /// Chain ID where the batch was executed
    pub chain_id: ChainId,
    /// Source LayerZero endpoint ID
    pub src_eid: u32,
    /// Latest LayerZero nonce that was processed
    pub nonce_lz: u64,
    /// Transaction ID of the batch transaction
    pub tx_id: TxId,
}
