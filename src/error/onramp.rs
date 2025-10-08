use super::invalid_params;
use thiserror::Error;

/// Errors related to onramp operations.
#[derive(Debug, Error)]
pub enum OnrampError {
    /// Invalid secret provided for accessing onramp contact information.
    #[error("invalid secret")]
    InvalidSecret,
}

impl From<OnrampError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(err: OnrampError) -> Self {
        match err {
            OnrampError::InvalidSecret => invalid_params(err.to_string()),
        }
    }
}
