//! Helpers for serializing and deserializing signatures.

use alloy::{hex, primitives::PrimitiveSignature};
use serde::{Deserialize, Serializer};
use std::str::FromStr;

/// Serializes [`PrimitiveSignature`] as string.
pub fn serialize<S>(signature: &PrimitiveSignature, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(signature.as_bytes()))
}

/// Deserialize a [`PrimitiveSignature`] from a String.
pub fn deserialize<'de, D>(deserializer: D) -> Result<PrimitiveSignature, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    PrimitiveSignature::from_str(&s).map_err(serde::de::Error::custom)
}
