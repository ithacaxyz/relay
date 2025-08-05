pub mod gas_estimation;
pub mod price_calculator;

use crate::error::RelayError;
use crate::types::PartialIntent;
use alloy::primitives::Address;

#[derive(Debug, thiserror::Error)]
pub enum PricingError {
    #[error("Price oracle unavailable: {0}")]
    PriceOracleUnavailable(String),
    #[error("Gas estimation failed: {0}")]
    GasEstimationFailed(String),
    #[error("Invalid fee calculation: {0}")]
    InvalidFeeCalculation(String),
}

impl From<PricingError> for RelayError {
    fn from(err: PricingError) -> Self {
        RelayError::internal(err)
    }
}

pub struct IntentPricer<'a> {
    context: &'a PricingContext,
}

pub struct PricingContext {
    pub fee_token: Address,
    pub user_address: Address,
}

impl<'a> IntentPricer<'a> {
    pub fn new(context: &'a PricingContext) -> Self {
        Self { context }
    }

    pub async fn calculate_pricing(
        &self,
        _intent: &PartialIntent,
    ) -> Result<(), PricingError> {
        // Implementation would calculate pricing for the intent
        // This is a placeholder for the actual pricing logic
        todo!("Implement actual pricing logic")
    }
}