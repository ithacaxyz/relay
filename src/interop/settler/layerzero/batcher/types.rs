use crate::{
    interop::settler::{SettlementError, layerzero::EndpointId},
    transactions::TxId,
    types::Call3,
};
use alloy::primitives::{Address, ChainId};
use tokio::sync::{oneshot, watch};

/// Key for identifying unique LayerZero settlement paths (chain pair + settler)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SettlementPathKey {
    /// Destination chain ID
    pub chain_id: ChainId,
    /// Source LayerZero endpoint ID
    pub src_eid: EndpointId,
    /// Settler address
    pub settler_address: Address,
}

impl SettlementPathKey {
    /// Create a new settlement path key
    pub fn new(chain_id: ChainId, src_eid: EndpointId, settler_address: Address) -> Self {
        Self { chain_id, src_eid, settler_address }
    }
}

/// LayerZero settlement message to be batched with the following calls: `{ commitVerification,
/// lzReceive, settle }`.
#[derive(Debug, Clone)]
pub struct LayerZeroBatchMessage {
    /// Destination chain ID
    pub chain_id: ChainId,
    /// Source LayerZero endpoint ID  
    pub src_eid: EndpointId,
    /// LayerZero nonce for this message
    pub nonce: u64,
    /// The calls to execute: `{ commitVerification, lzReceive, settle }`
    pub calls: Vec<Call3>,
    /// Settler address for this message
    pub settler_address: Address,
}

impl LayerZeroBatchMessage {
    /// Get the settlement path key for this message
    pub fn path_key(&self) -> SettlementPathKey {
        SettlementPathKey::new(self.chain_id, self.src_eid, self.settler_address)
    }
}

/// Pending batch of LayerZero messages.
#[derive(Debug, Clone, Default)]
pub struct PendingBatch {
    /// Settlements that can be processed in this batch (gapless from current nonce)
    pub settlements: Vec<LayerZeroBatchMessage>,
    /// Total number of settlements available in the pool for this chain pair, including these
    /// ones.
    pub total_pool_available: usize,
}

impl PendingBatch {
    /// Create a new pending batch
    pub fn new(settlements: Vec<LayerZeroBatchMessage>, total_available: usize) -> Self {
        Self { settlements, total_pool_available: total_available }
    }

    /// Check if the batch is empty
    pub fn is_empty(&self) -> bool {
        self.settlements.is_empty()
    }

    /// Get the number of messages in this batch
    pub fn len(&self) -> usize {
        self.settlements.len()
    }
}

/// Messages for communicating with the `LayerZeroBatchPool`.
#[derive(Debug)]
pub enum LayerZeroPoolMessages {
    /// New settlement to process
    Settlement {
        /// The settlement message to process
        settlement: LayerZeroBatchMessage,
        /// Channel to send the result back
        response: oneshot::Sender<Result<(), SettlementError>>,
    },
    /// Get pending gapless batch starting from highest_nonce + 1
    GetPendingBatch {
        /// Settlement stream key
        key: SettlementPathKey,
        /// Current highest nonce confirmed
        highest_nonce: u64,
        /// Channel to send response
        response: oneshot::Sender<PendingBatch>,
    },
    /// Update highest nonce confirmed and remove/notify processed settlements
    UpdateHighestNonce {
        /// Settlement stream key
        key: SettlementPathKey,
        /// New highest nonce
        nonce: u64,
        /// Transaction ID that processed this nonce
        tx_id: TxId,
    },
    /// Get highest nonce for a specific chain/eid
    GetHighestNonce {
        /// Settlement stream key
        key: SettlementPathKey,
        /// Channel to send response
        response: oneshot::Sender<Option<u64>>,
    },
    /// Subscribe to pool size updates for a specific chain/eid
    Subscribe {
        /// Settlement stream key
        key: SettlementPathKey,
        /// Channel to send watch receiver
        response: oneshot::Sender<watch::Receiver<usize>>,
    },
}

/// Pending settlement entry containing the message and response channel
#[derive(Debug)]
pub struct PendingSettlementEntry {
    /// The LayerZero batch message
    pub message: LayerZeroBatchMessage,
    /// Channel to send the result back to the caller
    pub response_tx: oneshot::Sender<Result<(), SettlementError>>,
}

impl PendingSettlementEntry {
    /// Create a new pending settlement entry
    pub fn new(
        message: LayerZeroBatchMessage,
        response_tx: oneshot::Sender<Result<(), SettlementError>>,
    ) -> Self {
        Self { message, response_tx }
    }
}
