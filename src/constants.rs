//! Relay constants.

use alloy::{primitives::U256, uint};
use std::time::Duration;

/// Extra buffer added to UserOp gas estimates signed by P256 keys to cover execution overhead
/// and ensure sufficient gas is provided.
pub const P256_GAS_BUFFER: U256 = uint!(10_000_U256);

/// Extra buffer added to UserOp gas estimates to cover execution overhead
/// and ensure sufficient gas is provided.
pub const USER_OP_GAS_BUFFER: u64 = 25_000;

/// The default poll interval used by the relay clients.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(300);

/// Default number of incoming RPC connections.
pub const DEFAULT_RPC_DEFAULT_MAX_CONNECTIONS: u32 = 5_000;

/// Extra buffer added to transaction gas estimates to pass the contract 63/64 check.
pub const TX_GAS_BUFFER: u64 = 1_000_000; // todo: temporarily bumped to 1m from 50k to unblock

/// The Base Mainnet sequencer URL.
///
/// This is only suitable for submitted transactions via `eth_sendRawTransaction`, all other methods
/// are disabled.
pub const BASE_MAINNET_SEQUENCER_URL: &str = "https://mainnet-sequencer.base.org";

/// The Base Sepolia sequencer URL.
///
/// This is only suitable for submitted transactions via `eth_sendRawTransaction`, all other methods
/// are disabled.
pub const BASE_SEPOLIA_SEQUENCER_URL: &str = "https://sepolia-sequencer.base.org";

/// The public Base Mainnet RPC URL.
///
/// This endpoint is rate-limited.
/// See also <https://docs.base.org/chain/network-information>
pub const BASE_MAINNET_PUBLIC_RPC_URL: &str = "https://mainnet.base.org";

/// The public Base Sepolia RPC URL.
///
/// This endpoint is rate-limited.
/// See also <https://docs.base.org/chain/network-information>
pub const BASE_SEPOLIA_PUBLIC_RPC_URL: &str = "https://sepolia.base.org";

/// Default cap on maximum number of pending transactions per chain.
pub const DEFAULT_MAX_TRANSACTIONS: usize = 100;
