//! RPC key-related request and response types.

use crate::types::Key;
use alloy::primitives::{Address, B256};
use serde::{Deserialize, Serialize};

/// Request parameters for `wallet_getKeys`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetKeysParameters {
    /// Address of the account to get the keys for.
    pub address: Address,
}
