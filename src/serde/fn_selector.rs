//! Helpers for deserializing function selectors.

use std::str::FromStr;

use alloy::{json_abi::Function, primitives::FixedBytes};
use serde::{Deserialize, Deserializer};

/// Deserialize a function selector from either a string or a valid 4-byte array.
///
/// See [`Function::parse`].
pub fn deserialize<'de, D>(deserializer: D) -> Result<FixedBytes<4>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(deserializer)?;

    FixedBytes::<4>::from_str(s)
        .or_else(|_| Function::parse(s).map_err(serde::de::Error::custom).map(|f| f.selector()))
}
