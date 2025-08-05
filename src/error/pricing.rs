use thiserror::Error;

/// Errors related to pricing.
#[derive(Debug, Error)]
pub enum PricingError {
    /// Price oracle unavailable.
    #[error("Price oracle unavailable: {0}")]
    PriceOracleUnavailable(String),
    /// Gas estimation failed.
    #[error("Gas estimation failed: {0}")]
    GasEstimationFailed(String),
    /// Invalid fee calculation.
    #[error("Invalid fee calculation: {0}")]
    InvalidFeeCalculation(String),
}

impl From<PricingError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(err: PricingError) -> Self {
        super::internal_rpc(err.to_string())
    }
}