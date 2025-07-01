//! Types and traits for bridges to use for rebalancing liquidity.

use crate::liquidity::tracker::ChainAddress;
use alloy::primitives::{BlockNumber, U256, wrap_fixed_bytes};
use futures_util::Stream;
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, fmt::Debug};

mod simple;
pub use simple::{Funder, SimpleBridge};

wrap_fixed_bytes!(
    /// Identifier for a cross-chain transfer.
    pub struct TransferId<32>;
);

/// States of a [`Transfer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferState {
    Sent(BlockNumber),
    OutboundFailed,
    Completed(BlockNumber),
    InboundFailed,
}

/// A cross-chain transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transfer {
    /// Unique identifier of the transfer.
    pub id: TransferId,
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
    TransferState(TransferId, TransferState),
}

/// An abstraction over a bridge that is able to accept bridging requests and driving them to
/// completion.
pub trait Bridge: Stream<Item = BridgeEvent> + Send + Sync + Unpin + Debug {
    /// Unique identifier of the bridge.
    fn id(&self) -> &'static str;

    /// Returns true if the bridge supports the given [`CoinKind`] on the given [`ChainId`].
    fn supports(&self, src: ChainAddress, dst: ChainAddress) -> bool;

    /// Initiates a cross-chain transfer. This is expected to spawn a new task that would parse
    /// `data` and determine the current state of the transfer.
    ///
    /// The spawned task is responsinble for updating the `data` in storage.
    fn advance(&mut self, transfer: Transfer);
}
