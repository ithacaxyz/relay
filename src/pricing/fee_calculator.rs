//! Fee calculation coordination using focused components.

use crate::{
    chains::Chain,
    price::PriceOracle,
    error::PricingError,
    pricing::{price_converter::PriceConverter, l1_fee_estimator::L1FeeEstimator},
    types::{Intent, Token},
};
use alloy::{
    primitives::U256,
    providers::{Provider, utils::Eip1559Estimation},
};

/// Fee calculator coordinator that combines price conversion and L1 fee estimation.
///
/// This component coordinates between focused price conversion and L1 fee estimation
/// components to provide complete fee calculations for transactions.
#[derive(Debug)]
pub struct FeeCalculator<'a> {
    price_converter: PriceConverter<'a>,
}

impl<'a> FeeCalculator<'a> {
    /// Creates a new fee calculator with the given price oracle.
    pub fn new(price_oracle: &'a PriceOracle) -> Self {
        Self {
            price_converter: PriceConverter::new(price_oracle),
        }
    }

    /// Calculates payment per gas in fee token units.
    ///
    /// Delegates to the focused price converter component.
    pub async fn calculate_payment_per_gas(
        &self,
        fee_estimate: &Eip1559Estimation,
        token: &Token,
    ) -> Result<f64, PricingError> {
        self.price_converter.calculate_payment_per_gas(fee_estimate, token).await
    }

    /// Calculates extra payment amount in native units.
    ///
    /// This includes L1 data availability fees for rollup chains.
    pub async fn estimate_extra_fee<P: Provider>(
        &self,
        provider: &P,
        chain: &Chain,
        intent: &Intent,
    ) -> Result<U256, PricingError> {
        L1FeeEstimator::estimate_l1_fee(provider, chain, intent).await
    }

    /// Converts native token amount to fee token amount.
    ///
    /// Delegates to the focused price converter component.
    pub async fn convert_native_to_token(
        &self,
        native_amount: U256,
        token: &Token,
    ) -> Result<U256, PricingError> {
        self.price_converter.convert_native_to_token(native_amount, token).await
    }
}
