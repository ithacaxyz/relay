//! Relay constants.

use alloy::hex;

/// Additional gas overhead for the inner entrypoint during execution,
/// used to adjust gas estimation.
pub const INNER_ENTRYPOINT_GAS_OVERHEAD: u64 = 100_000;

/// Extra buffer added to UserOp gas estimates to cover execution overhead
/// and ensure sufficient gas is provided.
pub const USER_OP_GAS_BUFFER: u64 = 25_000;

/// Extra buffer added to transaction gas estimates to pass the contract 63/64 check.
pub const TX_GAS_BUFFER: u64 = 50_000;

/// The EIP-7702 delegation designator.
pub const EIP7702_DELEGATION_DESIGNATOR: [u8; 3] = hex!("0xef0100");

/// The EIP-7702 delegation designator for a cleared delegation.
pub const EIP7702_CLEARED_DELEGATION: [u8; 23] =
    hex!("0xef01000000000000000000000000000000000000000000");
