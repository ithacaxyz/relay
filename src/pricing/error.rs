//! Pricing-specific error types.

/// Errors that can occur during price calculation and fee estimation.
#[derive(Debug, thiserror::Error)]
pub enum PricingError {
    /// Fee history is unavailable or invalid.
    #[error("Fee history unavailable: {0}")]
    FeeHistoryUnavailable(String),

    /// Gas estimation failed.
    #[error("Gas estimation failed: {0}")]
    GasEstimationFailed(String),

    /// Price calculation failed.
    #[error("Price calculation failed: {0}")]
    PriceCalculationFailed(String),

    /// Quote generation failed.
    #[error("Quote generation failed: {0}")]
    QuoteGenerationFailed(String),

    /// Price oracle is unavailable.
    #[error("Price oracle unavailable for token: {0}")]
    PriceOracleUnavailable(String),

    /// Invalid pricing context provided.
    #[error("Invalid pricing context: {0}")]
    InvalidContext(String),

    /// Fee token not supported for pricing.
    #[error("Unsupported fee token: {0}")]
    UnsupportedFeeToken(String),
}