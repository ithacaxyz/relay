//! Shared primitive types.
mod account;
pub use account::*;

mod account_registry;
pub use account_registry::*;

mod action;
pub use action::*;

mod asset_diff;
pub use asset_diff::*;

mod coin;
pub use coin::*;

mod coin_registry;
pub use coin_registry::*;

mod entrypoint;
pub use entrypoint::*;

mod tokens;
pub use tokens::*;

mod key;
use alloy::primitives::Uint;
pub use key::*;

mod op;
pub use op::*;

mod onramp;
pub use onramp::*;

mod signed;
pub use signed::*;

mod quote;
pub use quote::*;

pub mod rpc;

mod token;
pub use token::*;

mod call;
pub use call::*;

mod webauthn;
pub use webauthn::*;

mod simulator;
pub use simulator::*;

mod storage;
pub use storage::*;

/// A 40 bit integer.
pub type U40 = Uint<40, 1>;
