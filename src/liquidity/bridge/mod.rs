//! Types and traits for bridges to use for rebalancing liquidity.

use crate::liquidity::tracker::ChainAddress;
use alloy::primitives::{BlockNumber, U256, wrap_fixed_bytes};
use futures_util::Stream;
use std::fmt::Debug;

mod simple;
pub use simple::{Funder, SimpleBridge};

wrap_fixed_bytes!(
    /// Identifier for a cross-chain transfer.
    pub struct TransferId<32>;
);

/// A cross-chain transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transfer {
    /// Unique identifier of the transfer.
    pub id: TransferId,
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
    TransferSent(Transfer, BlockNumber),
    /// Emitted when we've failed to pull funds from the source chain.
    OutboundFailed(Transfer),
    /// Emitted when funds were successfully bridged to the destination chain.
    TransferCompleted(Transfer, BlockNumber),
    /// Worst case — we've pulled funds from the source chain but were not able to deliver them.
    InboundFailed(Transfer),
}

/// An abstraction over a bridge that is able to accept bridging requests and driving them to
/// completion.
pub trait Bridge: Stream<Item = BridgeEvent> + Send + Sync + Unpin + Debug {
    /// Returns true if the bridge supports the given [`CoinKind`] on the given [`ChainId`].
    fn supports(&self, src: ChainAddress, dst: ChainAddress) -> bool;

    /// Initiates a cross-chain transfer. This is expected to spawn a new task
    fn send(&mut self, src: ChainAddress, dst: ChainAddress, amount: U256) -> eyre::Result<()>;

    /// Returns a list of transfers that are in progress.
    fn transfers_in_progress(&self) -> &[Transfer];
}
