//! Relay constants.

/// Additional gas overhead for the inner entrypoint during execution,
/// used to adjust gas estimation.
pub const INNER_ENTRYPOINT_GAS_OVERHEAD: u64 = 100_000;

/// Extra buffer added to UserOp gas estimates to cover execution overhead
/// and ensure sufficient gas is provided.
pub const USER_OP_GAS_BUFFER: u64 = 25_000;

/// Extra buffer added to transaction gas estimates to pass the contract 63/64 check.
pub const TX_GAS_BUFFER: u64 = 50_000;
