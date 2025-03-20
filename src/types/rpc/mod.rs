//! RPC request and response types.

mod account;
pub use account::*;

mod calls;
pub use calls::*;

mod keys;
pub use keys::*;

mod permission;
pub use permission::*;

use alloy::primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};

/// Represents extra request values.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    /// ERC20 token to pay for the gas of the calls.
    ///
    /// Defaults to the native token.
    #[serde(default)]
    pub fee_token: Address,
    /// Key (hash) that will be used to sign the request.
    pub key_hash: B256,
    /// Nonce.
    pub nonce: U256,
}
