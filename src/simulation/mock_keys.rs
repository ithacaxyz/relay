//! Mock key generation utilities for simulation.

use crate::{
    error::{KeysError, RelayError},
    simulation::error::SimulationError,
    types::{KeyType, KeyWith712Signer},
};
use alloy::primitives::B256;

/// Mock key generator for simulation purposes.
#[derive(Debug)]
pub struct MockKeyGenerator;

impl MockKeyGenerator {
    /// Generates a random admin key for the specified key type.
    ///
    /// This is used during simulation to create a mock signer for testing
    /// intent execution without requiring actual user keys.
    pub fn generate_admin_key(key_type: KeyType) -> Result<KeyWith712Signer, SimulationError> {
        KeyWith712Signer::random_admin(key_type)
            .map_err(|e| SimulationError::MockKeyFailed(e.to_string()))?
            .ok_or_else(|| {
                SimulationError::MockKeyFailed(format!("Unsupported key type: {key_type:?}"))
            })
    }

    /// Generates a random session (non-admin) key for the specified key type.
    ///
    /// This creates a key with limited permissions, useful for testing
    /// scenarios with restricted access.
    pub fn generate_session_key(key_type: KeyType) -> Result<KeyWith712Signer, SimulationError> {
        KeyWith712Signer::random_session(key_type)
            .map_err(|e| SimulationError::MockKeyFailed(e.to_string()))?
            .ok_or_else(|| {
                SimulationError::MockKeyFailed(format!("Unsupported key type: {key_type:?}"))
            })
    }

    /// Generates a mock admin key with a specific key value.
    ///
    /// This is useful for deterministic testing scenarios where
    /// the same key needs to be generated repeatedly.
    pub fn generate_admin_key_with_value(
        key_type: KeyType,
        key_value: B256,
    ) -> Result<KeyWith712Signer, SimulationError> {
        KeyWith712Signer::mock_admin_with_key(key_type, key_value)
            .map_err(|e| SimulationError::MockKeyFailed(e.to_string()))?
            .ok_or_else(|| {
                SimulationError::MockKeyFailed(format!("Unsupported key type: {key_type:?}"))
            })
    }

    /// Generates a standard Secp256k1 admin key for quick simulation.
    ///
    /// This is the most common key type used in testing and provides
    /// a convenient shorthand for the general case.
    pub fn generate_default_admin_key() -> Result<KeyWith712Signer, SimulationError> {
        Self::generate_admin_key(KeyType::Secp256k1)
    }

    /// Validates that a key type is supported for mock key generation.
    pub fn is_supported_key_type(key_type: &KeyType) -> bool {
        matches!(key_type, KeyType::Secp256k1 | KeyType::P256 | KeyType::WebAuthnP256)
    }
}

/// Extension trait for converting key generation errors to relay errors.
pub trait MockKeyErrorExt {
    /// Converts a mock key generation result to a relay error result.
    fn to_relay_error(self) -> Result<KeyWith712Signer, RelayError>;
}

impl MockKeyErrorExt for Result<KeyWith712Signer, SimulationError> {
    fn to_relay_error(self) -> Result<KeyWith712Signer, RelayError> {
        self.map_err(|e| match e {
            SimulationError::MockKeyFailed(_) => RelayError::Keys(KeysError::UnsupportedKeyType),
            _ => RelayError::Simulation(e),
        })
    }
}
