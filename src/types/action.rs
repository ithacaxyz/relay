//! RPC action types.

use alloy::primitives::ChainId;
use serde::{Deserialize, Serialize};

use super::{PartialUserOp, UserOp};

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
}

/// An action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Action {
    /// The user op.
    pub op: UserOp,
    /// The destination chain ID.
    pub chain_id: ChainId,
}
