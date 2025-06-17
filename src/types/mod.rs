//! Shared primitive types.
mod account;
pub use account::*;

mod action;
pub use action::*;

mod asset;
pub use asset::*;

mod asset_diff;
pub use asset_diff::*;

mod coin;
pub use coin::*;

mod coin_registry;
pub use coin_registry::*;

mod contracts;
pub use contracts::*;

mod orchestrator;
pub use orchestrator::*;

mod tokens;
pub use tokens::*;

mod key;
use alloy::primitives::Uint;
pub use key::*;

mod intent;
pub use intent::*;

mod intents;
pub use intents::*;

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

mod merkle;
pub use merkle::*;
