//! Pricing-specific error types.

use alloy::primitives::Address;

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

    /// Fee token not supported for pricing.
    #[error("Unsupported fee token: {0}")]
    UnsupportedFeeToken(Address),

    /// Token not supported by price oracle.
    #[error("Unsupported token: {0}")]
    UnsupportedToken(Address),

    /// Price unavailable for token.
    #[error("Price unavailable for token: {0}")]
    UnavailablePrice(Address),
}
