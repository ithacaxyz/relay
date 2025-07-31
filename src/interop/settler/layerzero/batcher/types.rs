use crate::{
    interop::settler::{
        SettlementError,
        layerzero::{EndpointId, LZChainConfig},
    },
    transactions::TxId,
    types::Call3,
};
use alloy::{
    primitives::{Address, ChainId, map::HashMap},
    providers::DynProvider,
};
use std::sync::Arc;
use tokio::sync::oneshot;

/// LayerZero settlement message to be batched with the following calls: { commitVerification,
/// lzReceive, settle }.
#[derive(Debug, Clone)]
pub struct LayerZeroBatchMessage {
    /// Destination chain ID
    pub chain_id: ChainId,
    /// Source LayerZero endpoint ID  
    pub src_eid: EndpointId,
    /// LayerZero nonce for this message
    pub nonce: u64,
    /// The calls to execute: { commitVerification, lzReceive, settle }
    pub calls: Vec<Call3>,
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

/// Messages for communicating with the LayerZeroBatchPool.
#[derive(Debug)]
pub enum LayerZeroPoolMessages {
    /// New settlement to process
    Settlement(LayerZeroBatchMessage, oneshot::Sender<Result<(), SettlementError>>),
    /// Get pending gapless batch starting from highest_nonce + 1
    GetPendingBatch {
        /// Chain ID to get batch for
        chain_id: ChainId,
        /// Source endpoint ID
        src_eid: EndpointId,
        /// Current highest nonce confirmed
        highest_nonce: u64,
        /// Channel to send response
        response: oneshot::Sender<PendingBatch>,
    },
    /// Update highest nonce confirmed
    UpdateHighestNonce(ChainId, EndpointId, u64, TxId),
    /// Remove processed settlements up to and including highest_nonce
    RemoveProcessed {
        /// Chain ID
        chain_id: ChainId,
        /// Source endpoint ID
        src_eid: EndpointId,
        /// Highest nonce to remove up to
        highest_nonce: u64,
    },
    /// Get highest nonce for a specific chain/eid
    GetHighestNonce {
        /// Chain ID
        chain_id: ChainId,
        /// Source endpoint ID
        src_eid: EndpointId,
        /// Channel to send response
        response: oneshot::Sender<Option<u64>>,
    },
}

/// Chain configurations for LayerZero
#[derive(Debug, Clone)]
pub struct ChainConfigs(Arc<HashMap<ChainId, LZChainConfig>>);

impl ChainConfigs {
    /// Create new ChainConfigs from components
    pub fn new(
        endpoint_ids: &HashMap<ChainId, EndpointId>,
        endpoint_addresses: &HashMap<ChainId, Address>,
        providers: &HashMap<ChainId, DynProvider>,
        settler_address: Address,
    ) -> Self {
        let configs: HashMap<ChainId, LZChainConfig> = endpoint_ids
            .iter()
            .filter_map(|(chain_id, endpoint_id)| {
                let endpoint_address = endpoint_addresses.get(chain_id)?;
                let provider = providers.get(chain_id)?;

                Some((
                    *chain_id,
                    LZChainConfig {
                        endpoint_id: *endpoint_id,
                        endpoint_address: *endpoint_address,
                        provider: provider.clone(),
                        settler_address,
                    },
                ))
            })
            .collect();

        Self(Arc::new(configs))
    }

    /// Get a chain config by chain ID
    pub fn get(&self, chain_id: &ChainId) -> Option<&LZChainConfig> {
        self.0.get(chain_id)
    }

    /// Iterate over all chain configs
    pub fn iter(&self) -> impl Iterator<Item = (&ChainId, &LZChainConfig)> {
        self.0.iter()
    }
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
