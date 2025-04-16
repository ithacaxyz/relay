//! Helpers for serializing and deserializing [`Context`].

use opentelemetry::{Context, global};
use serde::{self, Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;

/// Serializes [`Context`] as a `HashMap<String, String>`.
pub fn serialize<S>(ctx: &Context, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut carrier = HashMap::new();
    global::get_text_map_propagator(|propagator| {
        propagator.inject_context(ctx, &mut carrier);
    });
    carrier.serialize(serializer)
}

/// Deserializes a `HashMap<String, String>` into a [`Context`].
pub fn deserialize<'de, D>(deserializer: D) -> Result<Context, D::Error>
where
    D: Deserializer<'de>,
{
    let carrier = HashMap::<String, String>::deserialize(deserializer)?;
    Ok(global::get_text_map_propagator(|propagator| propagator.extract(&carrier)))
}
