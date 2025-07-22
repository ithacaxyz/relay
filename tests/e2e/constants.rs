//! Relay end-to-end test constants

use alloy::primitives::{Address, B256, FixedBytes, address, b256, fixed_bytes};

pub const EOA_PRIVATE_KEY: B256 =
    b256!("0x174aca1574aca1574aca1574aca1574aca1574aca1574aca1574aca1574aca15");

pub const SIGNERS_MNEMONIC: &str =
    "forget sound story reveal safe minimum wasp mechanic solar predict harsh catch";

pub const DEFAULT_EXECUTE_SELECTOR: FixedBytes<4> = fixed_bytes!("0x32323232");

pub const DEFAULT_EXECUTE_TO: Address = address!("0x3232323232323232323232323232323232323232");

pub const FIRST_RELAY_SIGNER: B256 =
    b256!("0xab78933d36d3e049cc43e1f72845a6c03cdadf8557027bc4895053e8351b71cd");

pub const DEPLOYER_PRIVATE_KEY: B256 =
    b256!("0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6");

pub const LAYERZERO_DEPLOYER_ADDRESS: Address =
    address!("0x8fd379246834eac74B8419FfdA202CF8051F7A03");

pub const LAYERZERO_DEPLOYER_PRIVATE_KEY: B256 =
    b256!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
