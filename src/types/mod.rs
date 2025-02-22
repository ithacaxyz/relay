//! Shared primitive types.
mod account;
pub use account::*;

mod action;
pub use action::*;

mod coin;
pub use coin::*;

mod entrypoint;
pub use entrypoint::*;

mod erc20;
pub use erc20::*;

mod key;
use alloy::primitives::{B256, Uint};
pub use key::*;

mod op;
pub use op::*;

mod signed;
pub use signed::*;

mod quote;
pub use quote::*;

mod token;
pub use token::*;

mod call;
pub use call::*;

mod webauthn;
pub use webauthn::*;

/// A 40 bit integer.
pub type U40 = Uint<40, 1>;

/// A [`UserOp`] hash.
pub type UserOpHash = B256;

/// A batch hash.
///
/// A batch is a collection of one or more [`UserOp`]s that are executed atomically.
pub type BatchHash = B256;
