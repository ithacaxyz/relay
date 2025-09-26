//! Shared primitive types.
use serde::{Deserialize, Serialize};

mod account;
pub use account::*;

mod asset;
pub use asset::*;

mod simulation_assets;
pub use simulation_assets::*;

mod contracts;
pub use contracts::*;

mod orchestrator;
pub use orchestrator::*;

mod tokens;
pub use tokens::*;

mod key;
use alloy::primitives::{Address, Uint};
pub use key::*;

mod intent;
pub use intent::*;

mod intents;
pub use intents::*;

mod slots;
pub use slots::*;

mod interop;
pub use interop::*;

mod layerzero;
pub use layerzero::*;

mod signed;
pub use signed::*;

mod quote;
pub use quote::*;

mod transaction;
pub use transaction::*;

pub mod rpc;

mod call;
pub use call::*;

mod webauthn;
pub use webauthn::*;

mod simulator;
pub use simulator::*;

mod storage;
pub use storage::*;

mod merkle;
pub use merkle::*;

mod settler;
pub use settler::*;

mod escrow;
pub use escrow::*;

mod funder;
pub use funder::*;

mod multicall;
pub use multicall::*;

mod cast_debug;
pub use cast_debug::*;

/// A 40 bit integer.
pub type U40 = Uint<40, 1>;

/// The health response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Health {
    /// The status (usually OK) of the RPC.
    pub status: String,
    /// The version of the RPC.
    pub version: String,
    /// The address of the quote signer.
    pub quote_signer: Address,
}
