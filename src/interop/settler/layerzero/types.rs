use alloy::primitives::{Address, Bytes, ChainId, FixedBytes};
use serde::{Deserialize, Serialize};

use crate::types::rpc::BundleId;

/// LayerZero packet information for cross-chain messaging
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LayerZeroPacketInfo {
    /// Bundle identifier
    pub bundle_id: BundleId,
    /// Source chain ID
    pub src_chain_id: ChainId,
    /// Destination chain ID
    pub dst_chain_id: ChainId,
    /// Nonce for ordering
    pub nonce: u64,
    /// Sender address
    pub sender: Address,
    /// Receiver address
    pub receiver: Address,
    /// Global unique identifier
    pub guid: FixedBytes<32>,
    /// Message payload
    pub message: Bytes,
}
