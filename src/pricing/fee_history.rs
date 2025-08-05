//! Fee history analysis and EIP-1559 estimation utilities.

use crate::error::PricingError;
use alloy::{
    primitives::U256,
    providers::{
        Provider,
        utils::{EIP1559_FEE_ESTIMATION_PAST_BLOCKS, Eip1559Estimation, Eip1559Estimator},
    },
    rpc::types::FeeHistory,
};
use tracing::instrument;

/// Fee history analyzer for EIP-1559 gas price estimation.
#[derive(Debug)]
pub struct FeeHistoryAnalyzer;

impl FeeHistoryAnalyzer {
    /// Fetches fee history and analyzes it to produce fee estimates.
    #[instrument(skip_all)]
    pub async fn fetch_and_analyze<P: Provider>(
        provider: &P,
        priority_fee_percentile: f64,
    ) -> Result<Eip1559Estimation, PricingError> {
        // Fetch fee history
        let fee_history = provider
            .get_fee_history(
                EIP1559_FEE_ESTIMATION_PAST_BLOCKS,
                Default::default(),
                &[priority_fee_percentile],
            )
            .await
            .map_err(|e| PricingError::FeeHistoryUnavailable(e.to_string()))?;

        // Estimate fees from history
        Self::estimate_fees(&fee_history)
    }

    /// Estimates EIP-1559 fees from fee history data.
    pub fn estimate_fees(fee_history: &FeeHistory) -> Result<Eip1559Estimation, PricingError> {
        let latest_base_fee = fee_history.latest_block_base_fee().ok_or_else(|| {
            PricingError::FeeHistoryUnavailable("No base fee in fee history".to_string())
        })?;

        let reward = fee_history.reward.as_ref().ok_or_else(|| {
            PricingError::FeeHistoryUnavailable("No reward data in fee history".to_string())
        })?;

        Ok(Eip1559Estimator::default().estimate(latest_base_fee, reward))
    }

    /// Calculates payment per gas in fee token units.
    ///
    /// Converts native gas price to fee token units using the provided exchange rate.
    pub fn calculate_payment_per_gas(
        native_fee_estimate: &Eip1559Estimation,
        token_decimals: u8,
        eth_price_in_token: f64,
    ) -> f64 {
        (native_fee_estimate.max_fee_per_gas as f64 * 10u128.pow(token_decimals as u32) as f64)
            / eth_price_in_token
    }

    /// Gets the priority fee from estimation as U256.
    pub fn get_priority_fee(estimate: &Eip1559Estimation) -> U256 {
        U256::from(estimate.max_priority_fee_per_gas)
    }

    /// Gets the max fee from estimation as U256.
    pub fn get_max_fee(estimate: &Eip1559Estimation) -> U256 {
        U256::from(estimate.max_fee_per_gas)
    }
}
