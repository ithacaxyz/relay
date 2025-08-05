use super::PricingError;
use crate::types::Token;
use alloy::primitives::U256;

pub struct FeeEstimate {
    pub max_fee_per_gas: u64,
    pub max_priority_fee_per_gas: u64,
    pub gas_limit: u64,
}

pub struct PriceCalculator<'a> {
    fee_estimate: &'a FeeEstimate,
}

impl<'a> PriceCalculator<'a> {
    pub fn new(fee_estimate: &'a FeeEstimate) -> Self {
        Self { fee_estimate }
    }

    pub fn calculate_payment_per_gas(
        &self,
        token: &Token,
        eth_price: f32,
    ) -> Result<U256, PricingError> {
        // Convert from wei to token units
        // Formula: (gas_price_wei * 10^token_decimals) / eth_price_in_token
        let eth_price_f64 = f64::from(eth_price);

        // Prevent division by zero
        if eth_price_f64 == 0.0 {
            return Err(PricingError::PriceOracleUnavailable("ETH price is zero".to_string()));
        }

        let payment_per_gas = (self.fee_estimate.max_fee_per_gas as f64
            * 10u128.pow(token.decimals as u32) as f64)
            / eth_price_f64;

        Ok(U256::from(payment_per_gas as u128))
    }

    pub fn calculate_total_fee(&self, gas_used: u64) -> U256 {
        U256::from(self.fee_estimate.max_fee_per_gas) * U256::from(gas_used)
    }
}