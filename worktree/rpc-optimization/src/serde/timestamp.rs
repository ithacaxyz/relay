//! Helpers for serializing and deserializing [`SystemTime`].

use serde::{self, Deserialize, Deserializer, Serializer};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Serializes [`SystemTime`] as the number of seconds since [`UNIX_EPOCH`].
pub fn serialize<S>(time: &SystemTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let timestamp = time.duration_since(UNIX_EPOCH).unwrap_or(Duration::from_secs(0)).as_secs();
    serializer.serialize_u64(timestamp)
}

/// Deserializes a number of seconds since [`UNIX_EPOCH`] into a [`SystemTime`].
pub fn deserialize<'de, D>(deserializer: D) -> Result<SystemTime, D::Error>
where
    D: Deserializer<'de>,
{
    let timestamp = u64::deserialize(deserializer)?;
    Ok(UNIX_EPOCH + Duration::from_secs(timestamp))
}
