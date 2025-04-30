//! Relay end-to-end test constants

use alloy::primitives::{Address, B256, FixedBytes, address, b256, fixed_bytes};

pub const EOA_PRIVATE_KEY: B256 =
    b256!("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");

pub const SIGNERS_MNEMONIC: &str =
    "forget sound story reveal safe minimum wasp mechanic solar predict harsh catch";

pub const DEFAULT_EXECUTE_SELECTOR: FixedBytes<4> = fixed_bytes!("0x32323232");

pub const DEFAULT_EXECUTE_TO: Address = address!("0x3232323232323232323232323232323232323232");

pub const FIRST_RELAY_SIGNER: B256 =
    b256!("0xab78933d36d3e049cc43e1f72845a6c03cdadf8557027bc4895053e8351b71cd");
