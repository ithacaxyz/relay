use crate::types::CoinKind;
use alloy::primitives::{Address, BlockNumber, ChainId, U256, wrap_fixed_bytes};
use futures_util::Stream;

mod simple;
pub use simple::{Funder, SimpleBridge};

wrap_fixed_bytes!(
    pub struct TransferId<32>;
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transfer {
    /// Unique identifier of the transfer.
    pub id: TransferId,
    /// Kind of the coin being transferred.
    pub kind: CoinKind,
    /// Address of the token being transferred.
    pub address: Address,
    /// Amount of the coin being transferred.
    pub amount: U256,
    /// Source chain.
    pub from: ChainId,
    /// Destination chain.
    pub to: ChainId,
}

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
pub trait Bridge: Stream<Item = BridgeEvent> + Send + Sync + Unpin {
    /// Returns true if the bridge supports the given [`CoinKind`] on the given [`ChainId`].
    fn supports(&self, kind: CoinKind, from: ChainId, to: ChainId) -> bool;

    /// Initiates a cross-chain transfer. This is expected to spawn a new task
    fn send(
        &mut self,
        kind: CoinKind,
        amount: U256,
        from: ChainId,
        to: ChainId,
    ) -> eyre::Result<()>;

    /// Returns a list of transfers that are in progress.
    fn transfers_in_progress(&self) -> &[Transfer];
}
