//! RPC request and response types.

mod account;
pub use account::*;

mod assets;
pub use assets::*;

mod calls;
pub use calls::*;

mod keys;
pub use keys::*;

mod permission;
pub use permission::*;

mod capabilities;
pub use capabilities::*;

mod faucet;
pub use faucet::*;

use alloy::primitives::{Address, U256};
use serde::{Deserialize, Serialize};

/// Represents extra request values.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    /// Payer of the gas
    ///
    /// Defaults to the EOA.
    pub fee_payer: Option<Address>,
    /// ERC20 token to pay for the gas of the calls.
    ///
    /// Defaults to the native token.
    pub fee_token: Option<Address>,
    /// Nonce.
    pub nonce: Option<U256>,
}
