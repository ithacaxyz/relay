//! RPC action types.

use alloy::primitives::ChainId;
use serde::{Deserialize, Serialize};

use super::PartialUserOp;

/// A partial action which differs from [`Action`] in that it contains a [`PartialUserOp`].
///
/// Used for estimations and simulations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartialAction {
    /// The user op.
    pub op: PartialUserOp,
    /// The destination chain ID.
    pub chain_id: ChainId,
    /// Whether it is a preop.
    pub is_preop: bool,
}
