//! Simulation-specific error types.

/// Errors that can occur during intent simulation.
#[derive(Debug, thiserror::Error)]
pub enum SimulationError {
    /// State override creation failed.
    #[error("State override creation failed: {0}")]
    StateOverrideFailed(String),

    /// Mock key generation failed.
    #[error("Mock key generation failed: {0}")]
    MockKeyFailed(String),

    /// Simulation execution failed.
    #[error("Simulation execution failed: {0}")]
    ExecutionFailed(String),

    /// Asset diff calculation failed.
    #[error("Asset diff calculation failed: {0}")]
    AssetDiffFailed(String),

    /// Invalid simulation context provided.
    #[error("Invalid simulation context: {0}")]
    InvalidContext(String),

    /// Orchestrator interaction failed.
    #[error("Orchestrator interaction failed: {0}")]
    OrchestratorFailed(String),
}