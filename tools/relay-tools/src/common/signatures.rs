use alloy::{dyn_abi::JsonAbiExt, hex, json_abi::Function, primitives::U256};
use once_cell::sync::Lazy;
use relay::types::Call;
use serde_json;
use std::{collections::HashMap, fs, path::PathBuf};
use tracing::warn;

/// Global instance of signatures, loaded once on first access
pub static SIGNATURES: Lazy<Signatures> = Lazy::new(Signatures::load_from_file);

/// Function signature database loaded from Foundry cache
pub struct Signatures {
    signatures: HashMap<[u8; 4], String>,
}

impl Signatures {
    /// Get the global signatures instance
    pub fn instance() -> &'static Self {
        &SIGNATURES
    }

    /// Load signatures from Foundry cache file
    fn load_from_file() -> Self {
        let mut signatures = HashMap::new();

        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let cache_path = PathBuf::from(home).join(".foundry/cache/signatures");

        let Ok(content) = fs::read_to_string(&cache_path) else {
            warn!(path = ?cache_path, "Failed to load function signatures");
            return Self { signatures };
        };

        // Parse as JSON with structure {"functions": {"0xSELECTOR": "signature", ...}}
        let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) else {
            warn!(path = ?cache_path, "Failed to parse signatures file as JSON");
            return Self { signatures };
        };

        if let Some(functions) = json.get("functions").and_then(|v| v.as_object()) {
            for (selector_str, sig_value) in functions {
                // Skip non-string signatures
                let Some(signature) = sig_value.as_str() else {
                    continue;
                };

                // Parse selector (format: "0x12345678")
                let selector_str = selector_str.strip_prefix("0x").unwrap_or(selector_str);
                let Ok(selector_bytes) = hex::decode(selector_str) else {
                    continue;
                };

                if selector_bytes.len() == 4 {
                    let mut selector = [0u8; 4];
                    selector.copy_from_slice(&selector_bytes);
                    signatures.insert(selector, signature.to_string());
                }
            }
        }

        Self { signatures }
    }

    /// Decode a call's function signature
    pub fn decode_call(&self, call: &Call) -> String {
        // Empty data means value transfer
        let Some(selector) = call.data.get(..4) else {
            return if call.value > U256::ZERO {
                "transfer()".to_string()
            } else {
                "call()".to_string()
            };
        };

        let mut selector_array = [0u8; 4];
        selector_array.copy_from_slice(selector);

        let Some(signature) = self.signatures.get(&selector_array) else {
            return format!("0x{}", hex::encode(selector));
        };

        let Ok(func) = Function::parse(signature) else {
            // Fallback to the raw signature if parsing fails
            return signature.to_string();
        };

        // Try to decode the actual parameter values
        if call.data.len() > 4 {
            let Ok(decoded) = func.abi_decode_input(&call.data[4..]) else {
                return func.signature();
            };

            let params = decoded.iter().map(|v| format!("{:?}", v)).collect::<Vec<_>>().join(", ");
            return format!("{}({})", func.name, params);
        }

        func.signature()
    }
}
