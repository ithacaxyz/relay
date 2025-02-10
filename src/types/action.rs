//! RPC action types.

use alloy::{eips::eip7702::SignedAuthorization, primitives::Address};
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
    /// An optional unsigned authorization item.
    ///
    /// The account in `op.eoa` will be delegated to this address.
    pub auth: Option<Address>,
}

/// An action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Action {
    /// The user op.
    pub op: UserOp,
    /// An optional authorization item.
    pub auth: Option<SignedAuthorization>,
}
