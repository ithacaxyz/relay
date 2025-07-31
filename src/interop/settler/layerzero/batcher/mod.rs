//! Batch processing for LayerZero settlements.
//!
//! Components:
//! - **LayerZeroBatchPool**: Manages pending settlements by (chain_id, src_eid)
//! - **LayerZeroBatchProcessor**: Processes batches sequentially with nonce ordering
//!
//! Features: Sequential processing, crash recovery, parallel chain processing.

mod pool;
mod processor;
mod types;

pub use pool::LayerZeroPoolHandle;
pub use processor::LayerZeroBatchProcessor;
pub use types::{ChainConfigs, LayerZeroBatchMessage, LayerZeroPoolMessages, PendingBatch};
