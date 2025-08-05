//! Price conversion utilities for token and native currency conversions.

use crate::{price::PriceOracle, error::PricingError, types::Token};
use alloy::{primitives::U256, providers::utils::Eip1559Estimation};
use tracing::instrument;

/// Price converter for handling conversions between native ETH and fee tokens.
#[derive(Debug)]
pub struct PriceConverter<'a> {
    price_oracle: &'a PriceOracle,
}

impl<'a> PriceConverter<'a> {
    /// Creates a new price converter with the given price oracle.
    pub fn new(price_oracle: &'a PriceOracle) -> Self {
        Self { price_oracle }
    }

    /// Calculates payment per gas in fee token units.
    ///
    /// Converts native gas price (in wei) to fee token units using the current exchange rate.
    #[instrument(skip_all)]
    pub async fn calculate_payment_per_gas(
        &self,
        fee_estimate: &Eip1559Estimation,
        token: &Token,
    ) -> Result<f64, PricingError> {
        // Get ETH price in token units
        let eth_price = self
            .price_oracle
            .eth_price(token.kind)
            .await
            .ok_or(PricingError::UnavailablePrice(token.address))?;

        // Convert from wei to token units
        // Formula: (gas_price_wei * 10^token_decimals) / eth_price_in_token
        let eth_price_f64 = f64::from(eth_price);

        // Prevent division by zero
        if eth_price_f64 == 0.0 {
            return Err(PricingError::PriceOracleUnavailable("ETH price is zero".to_string()));
        }

        let payment_per_gas = (fee_estimate.max_fee_per_gas as f64
            * 10u128.pow(token.decimals as u32) as f64)
            / eth_price_f64;

        Ok(payment_per_gas)
    }

    /// Converts native token amount to fee token amount.
    ///
    /// Used for converting ETH amounts to ERC20 token amounts.
    pub async fn convert_native_to_token(
        &self,
        native_amount: U256,
        token: &Token,
    ) -> Result<U256, PricingError> {
        let eth_price = self
            .price_oracle
            .eth_price(token.kind)
            .await
            .ok_or(PricingError::UnavailablePrice(token.address))?;

        // Convert from native to token units
        let token_amount =
            native_amount * U256::from(10u128.pow(token.decimals as u32)) / eth_price;

        Ok(token_amount)
    }
}