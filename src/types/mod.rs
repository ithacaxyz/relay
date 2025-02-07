//! Shared primitive types.
mod action;
pub use action::*;

mod entrypoint;
pub use entrypoint::*;

mod erc20;
pub use erc20::*;

mod key;
use alloy::primitives::Uint;
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

/// A 40 bit integer.
pub type U40 = Uint<40, 1>;
