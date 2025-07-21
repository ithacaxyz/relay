//! Pull gas transaction types and state management.

use serde::{Deserialize, Serialize};
use sqlx::Type;
use strum::{Display, EnumString};

/// States of a pull gas transaction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type, Display, EnumString)]
#[sqlx(type_name = "pull_gas_state", rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum PullGasState {
    /// Transaction is pending (created or sent to chain)
    Pending,
    /// Transaction confirmed successfully
    Completed,
    /// Transaction failed
    Failed,
}

impl PullGasState {
    /// Whether the transaction has succeeded.
    pub fn is_completed(&self) -> bool {
        matches!(self, Self::Completed)
    }
}
