//! Relay end-to-end test constants

use std::sync::LazyLock;

use alloy::{
    hex,
    primitives::{Address, B256, FixedBytes, address, b256, fixed_bytes},
};
use relay::signers::{DynSigner, P256Signer};

pub const EOA_PRIVATE_KEY: B256 =
    b256!("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");

pub const RELAY_PRIVATE_KEY: B256 =
    b256!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

pub const DEFAULT_EXECUTE_SELECTOR: FixedBytes<4> = fixed_bytes!("32323232");

pub const DEFAULT_EXECUTE_TO: Address = address!("3232323232323232323232323232323232323232");
