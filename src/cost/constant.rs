use alloy::{
    primitives::{Address, U256},
    providers::utils::Eip1559Estimation,
};
use tracing::info;

use super::CostEstimate;
use crate::error::EstimateFeeError;

/// A cost estimator that applies a constant rate.
#[derive(Debug, Default)]
pub struct ConstantRateCost(U256);

impl ConstantRateCost {
    /// Creates [Self] with a rate in eth.
    pub fn in_eth(rate: f64) -> Self {
        Self(U256::from((rate * 1e18) as u128))
    }

    /// Creates [Self] with a rate in wei.
    #[allow(unused)]
    pub fn in_wei(rate: u128) -> Self {
        Self(U256::from(rate))
    }
}

impl CostEstimate for ConstantRateCost {
    async fn estimate(
        &self,
        gas_estimate: u64,
        native_fee_estimate: Eip1559Estimation,
        payment_token: Option<Address>,
    ) -> Result<U256, EstimateFeeError> {
        // Effective gas price
        let gas_price = U256::from(
            native_fee_estimate.max_fee_per_gas + native_fee_estimate.max_priority_fee_per_gas,
        );

        let wei_cost = U256::from(gas_estimate) * gas_price;
        info!(eth=?wei_cost, "Cost.");

        if payment_token.is_some() {
            return Ok((wei_cost * U256::from(1e18)) / self.0);
        }

        Ok(wei_cost)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{primitives::address, providers::utils::Eip1559Estimation};

    #[tokio::test]
    async fn constant_cost() {
        let usdt = address!("dac17f958d2ee523a2206206994597c13d831ec7");
        let estimation_eip1559 =
            Eip1559Estimation { max_fee_per_gas: 3_500_000_000u128, max_priority_fee_per_gas: 0 };

        // (rate, expected multipler)
        let fixtures = [
            (ConstantRateCost::in_eth(1f64), 1),
            (ConstantRateCost::in_wei(1e18 as u128), 1),
            (ConstantRateCost::in_eth(0.5f64), 2),
            (ConstantRateCost::in_wei((0.5f64 * 1e18) as u128), 2),
        ];

        for (estimator, multiplier) in fixtures {
            assert_eq!(
                estimator.estimate(50_000, estimation_eip1559, None).await.unwrap(),
                estimator.estimate(50_000, estimation_eip1559, Some(usdt)).await.unwrap()
                    / U256::from(multiplier)
            );
        }
    }
}
