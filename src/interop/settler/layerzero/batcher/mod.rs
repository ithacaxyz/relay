//! LayerZero settlement batch processing system.
//!
//! Aggregates cross-chain settlements into multicall batches while maintaining strict nonce
//! ordering. Settlements arrive from LayerZeroSettler and are queued until they form gapless
//! sequences.
//!
//! ## Flow
//! 1. Settlements submitted via `LayerZeroPoolHandle::send_settlement_and_wait`
//! 2. Pool stores by (chain_id, src_eid) in nonce-ordered BTreeMaps
//! 3. Processor polls for gapless batches starting from highest confirmed nonce
//! 4. Batches up to 20 messages into multicall transactions
//! 5. Updates highest nonce on confirmation, notifying waiting callers
//!
//! ## Modules
//! - `types`: Message and batch structures, chain configurations
//! - `pool`: Settlement queue with gap detection and caller notification
//! - `processor`: Per-chain-pair tasks that build and execute batches

mod pool;
mod processor;
mod types;

pub use pool::LayerZeroPoolHandle;
pub use processor::LayerZeroBatchProcessor;
pub use types::{ChainConfigs, LayerZeroBatchMessage, LayerZeroPoolMessages, PendingBatch};
