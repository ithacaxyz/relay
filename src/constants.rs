//! Relay constants.

use alloy::hex;

/// Extra buffer added to UserOp gas estimates to cover execution overhead
/// and ensure sufficient gas is provided.
pub const USER_OP_GAS_BUFFER: u64 = 25_000;

/// Extra buffer added to transaction gas estimates to pass the contract 63/64 check.
pub const TX_GAS_BUFFER: u64 = 1_000_000; // todo: temporarily bumped to 1m from 50k to unblock

/// The EIP-7702 delegation designator.
pub const EIP7702_DELEGATION_DESIGNATOR: [u8; 3] = hex!("0xef0100");

/// The EIP-7702 delegation designator for a cleared delegation.
pub const EIP7702_CLEARED_DELEGATION: [u8; 23] =
    hex!("0xef01000000000000000000000000000000000000000000");
