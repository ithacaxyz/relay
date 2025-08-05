use thiserror::Error;

/// Errors related to simulation.
#[derive(Debug, Error)]
pub enum SimulationError {
    /// Provider error during simulation.
    #[error("Provider error: {0}")]
    Provider(String),
    /// Simulation failed.
    #[error("Simulation failed: {0}")]
    SimulationFailed(String),
    /// Invalid state override.
    #[error("Invalid state override")]
    InvalidStateOverride,
}

impl From<SimulationError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(err: SimulationError) -> Self {
        super::internal_rpc(err.to_string())
    }
}