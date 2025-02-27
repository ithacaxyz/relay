//! Helpers for serialization and deserialization of key roles.

use serde::{Deserialize, Deserializer, Serializer};

/// Deserialize a string into a boolean value.
///
/// - `"admin"` -> `true`
/// - `"normal"` -> `false`
/// - `"session"` -> `false`
pub fn deserialize<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(deserializer)?;
    match s {
        "admin" => Ok(true),
        "normal" | "session" => Ok(false),
        _ => Err(serde::de::Error::unknown_variant(s, &["admin", "normal", "session"])),
    }
}

/// Serialize a boolean value as `"admin"` (`true`) or `"normal"` (`false`).
pub fn serialize<S>(value: &bool, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        true => serializer.serialize_str("admin"),
        false => serializer.serialize_str("normal"),
    }
}
