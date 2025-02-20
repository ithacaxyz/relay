//! Relay end-to-end test constants

use std::sync::LazyLock;

use alloy::{
    hex,
    primitives::{address, b256, Address, B256},
};
use relay::signers::{DynSigner, P256Signer};

pub const EOA_ADDRESS: Address = address!("70997970c51812dc3a010c7d01b50e0d17dc79c8");

pub const EOA_PRIVATE_KEY: B256 =
    b256!("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");

pub const RELAY_PRIVATE_KEY: B256 =
    b256!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

pub const FAKE_ERC20: Address = address!("9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0");
