//! Simulation-specific error types and handling.

use thiserror::Error;

/// Errors related to intent simulation and execution.
#[derive(Debug, Error)]
pub enum SimulationError {
    /// Failed to create state overrides for simulation.
    #[error("State override creation failed: {0}")]
    StateOverrideFailed(String),

    /// Failed to generate mock key for simulation.
    #[error("Mock key generation failed: {0}")]
    MockKeyFailed(String),

    /// Intent execution failed during simulation.
    #[error("Execution failed: {0}")]
    ExecutionFailed(String),

    /// Failed to calculate asset diffs.
    #[error("Asset diff calculation failed: {0}")]
    AssetDiffFailed(String),

    /// Invalid simulation context provided.
    #[error("Invalid context: {0}")]
    InvalidContext(String),

    /// Orchestrator operation failed.
    #[error("Orchestrator failed: {0}")]
    OrchestratorFailed(String),
}
