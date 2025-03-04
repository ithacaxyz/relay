//! RPC key-related request and response types.

use alloy::primitives::Address;
use serde::{Deserialize, Serialize};

/// Request parameters for `wallet_getKeys`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetKeysParameters {
    /// Address of the account to get the keys for.
    pub address: Address,
}
