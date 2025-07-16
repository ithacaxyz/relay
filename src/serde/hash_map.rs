//! [`toml`] does not allow non-[`String`] keys for [`HashMap`], so we're working around this with a
//! helepr that (de)serializes keys as strings via [`ToString`] and [`FromStr`] implementations.

use alloy::primitives::map::HashMap;
use serde::{self, Deserialize, Deserializer, Serialize, Serializer, de::Error};
use std::{fmt::Display, hash::Hash, str::FromStr};

/// Serializes [`Duration`] as seconds.
pub fn serialize<S, K, V>(map: &HashMap<K, V>, serializer: S) -> Result<S::Ok, S::Error>
where
    K: ToString + Hash + Eq,
    V: Serialize,
    S: Serializer,
{
    map.iter().map(|(k, v)| (k.to_string(), v)).collect::<HashMap<_, _>>().serialize(serializer)
}

/// Deserializes seconds into a [`Duration`].
pub fn deserialize<'de, K, V, D>(deserializer: D) -> Result<HashMap<K, V>, D::Error>
where
    K: FromStr<Err: Display> + Hash + Eq,
    V: Deserialize<'de>,
    D: Deserializer<'de>,
{
    HashMap::<String, V>::deserialize(deserializer).and_then(|map| {
        map.into_iter()
            .map(|(k, v)| K::from_str(&k).map(|k| (k, v)).map_err(D::Error::custom))
            .collect()
    })
}
