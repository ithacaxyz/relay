//! Helpers for serializing and deserializing [`Duration`].

use serde::{self, Deserialize, Deserializer, Serializer};
use std::time::Duration;

/// Serializes [`Duration`] as seconds.
pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let duration = duration.as_secs();
    serializer.serialize_u64(duration)
}

/// Deserializes seconds into a [`Duration`].
pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let duration = u64::deserialize(deserializer)?;
    Ok(Duration::from_secs(duration))
}
