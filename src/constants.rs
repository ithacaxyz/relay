//! Relay constants.

use alloy::{primitives::U256, uint};
use std::time::Duration;

/// Extra buffer added to Intent gas estimates signed by P256 keys to cover execution overhead
/// and ensure sufficient gas is provided.
///
/// P256 signature verification has high gas usage variance and the 10_000 value seems to be a safe
/// bet.
pub const P256_GAS_BUFFER: U256 = uint!(10_000_U256);

/// Extra buffer accounting for the cost of a cold storage write.
///
/// 20_000 - 2900 gas
pub const COLD_SSTORE_GAS_BUFFER: U256 = uint!(17_100_U256);

/// Extra buffer added to Intent gas estimates to cover execution overhead
/// and ensure sufficient gas is provided.
pub const INTENT_GAS_BUFFER: u64 = 0;

/// The default poll interval used by the relay clients.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(300);

/// Default number of incoming RPC connections.
pub const DEFAULT_RPC_DEFAULT_MAX_CONNECTIONS: u32 = 5_000;

/// Extra buffer added to transaction gas estimates to pass the contract 63/64 check.
pub const TX_GAS_BUFFER: u64 = 0;

/// Default cap on maximum number of pending transactions per chain.
pub const DEFAULT_MAX_TRANSACTIONS: usize = 100;

/// Default number of signers to derive from mnemonic and use for sending transactions.
pub const DEFAULT_NUM_SIGNERS: usize = 16;

/// Duration for escrow refunds in seconds.
///
/// After this duration, escrowed funds can be refunded if settlement hasn't occurred.
pub const ESCROW_REFUND_DURATION_SECS: u64 = 3600; // 1 hour

/// Length of the salt used for escrow operations.
///
/// This is used to generate unique escrow IDs.
pub const ESCROW_SALT_LENGTH: usize = 12;
