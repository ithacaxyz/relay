//! Price calculation utilities for converting between native and fee token prices.

use crate::{
    chains::Chain,
    price::PriceOracle,
    pricing::error::PricingError,
    provider::ProviderExt,
    types::{Intent, Token},
};
use alloy::{
    primitives::{Address, U256},
    providers::utils::Eip1559Estimation,
};
use tracing::instrument;

/// Price calculator for fee token conversions.
#[derive(Debug)]
pub struct PriceCalculator<'a> {
    price_oracle: &'a PriceOracle,
}

impl<'a> PriceCalculator<'a> {
    /// Creates a new price calculator with the given price oracle.
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

    /// Calculates extra payment amount in native units.
    ///
    /// This includes L1 data availability fees for Optimism rollups.
    #[instrument(skip_all)]
    pub async fn estimate_extra_fee<P: alloy::providers::Provider>(
        &self,
        provider: &P,
        chain: &Chain,
        intent: &Intent,
    ) -> Result<U256, PricingError> {
        // Include the L1 DA fees if we're on an OP rollup
        let fee = if chain.is_optimism {
            // Create a dummy transaction with all fields set to max values
            // to ensure calldata is largest possible
            use alloy::{
                consensus::{SignableTransaction, TxEip1559},
                signers::Signature,
            };

            let tx = TxEip1559 {
                chain_id: chain.chain_id,
                nonce: u64::MAX,
                gas_limit: u64::MAX,
                max_fee_per_gas: u128::MAX,
                max_priority_fee_per_gas: u128::MAX,
                to: (!Address::ZERO).into(),
                input: intent.encode_execute(),
                ..Default::default()
            };
            let signature = Signature::new(U256::MAX, U256::MAX, true);

            let encoded = {
                let tx = tx.into_signed(signature);
                let mut buf = Vec::with_capacity(tx.eip2718_encoded_length());
                tx.eip2718_encode(&mut buf);
                buf
            };

            provider
                .estimate_l1_fee(encoded.into())
                .await
                .map_err(|e| PricingError::PriceCalculationFailed(e.to_string()))?
        } else {
            U256::ZERO
        };

        Ok(fee)
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
