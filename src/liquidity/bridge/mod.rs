//! Types and traits for bridges to use for rebalancing liquidity.

use crate::liquidity::tracker::ChainAddress;
use alloy::primitives::{BlockNumber, U256, wrap_fixed_bytes};
use futures_util::Stream;
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, fmt::Debug, pin::Pin};

mod simple;
pub use simple::SimpleBridge;

wrap_fixed_bytes!(
    /// Identifier for a cross-chain transfer.
    pub struct BridgeTransferId<32>;
);

/// States of a [`Transfer`].
#[derive(Debug, Clone, Default, Copy, PartialEq, Eq)]
pub enum BridgeTransferState {
    /// Initial state.
    #[default]
    Pending,
    /// Initial transaction for the transfer has been sent. Once this state is reached, liquidity
    /// should be unlocked as it's already pulled on-chain.
    Sent(BlockNumber),
    /// Outbound transfer failed.
    OutboundFailed,
    /// Transfer completed and funds have been delivered to the destination chain.
    Completed(BlockNumber),
    /// Inbound transfer failed.
    InboundFailed,
}

/// A cross-chain transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeTransfer {
    /// Unique identifier of the transfer.
    pub id: BridgeTransferId,
    /// Bridge that is handling the transfer.
    pub bridge_id: Cow<'static, str>,
    /// Source asset.
    pub from: ChainAddress,
    /// Destination asset.
    pub to: ChainAddress,
    /// Amount of the coin being transferred.
    pub amount: U256,
}

/// Events emitted by a bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeEvent {
    /// Emitted when funds are pulled from the source chain.
    TransferState(BridgeTransferId, BridgeTransferState),
}

/// An abstraction over a bridge that is able to accept bridging requests and driving them to
/// completion.
pub trait Bridge: Stream<Item = BridgeEvent> + Send + Sync + Unpin + Debug {
    /// Unique identifier of the bridge.
    fn id(&self) -> &'static str;

    /// Returns true if the bridge supports bridging the given assets.
    fn supports(&self, src: ChainAddress, dst: ChainAddress) -> bool;

    /// Triggers processing of the given transfer. The bridge is expected to return a future that
    /// would advance the transfer progress based on internally saved `bridge_data` in storage.`
    fn process(&self, transfer: BridgeTransfer) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}
