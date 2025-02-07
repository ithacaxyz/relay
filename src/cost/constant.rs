use alloy::primitives::Address;

use super::CostEstimate;
use crate::error::EstimateFeeError;

/// A cost estimator that applies a constant rate.
#[derive(Debug, Default)]
pub struct ConstantRateCost(u128);

impl ConstantRateCost {
    /// Creates [Self] with a rate in eth.
    pub fn in_eth(rate: f64) -> Self {
        Self::in_wei((rate * 1e18) as u128)
    }

    /// Creates [Self] with a rate in wei.
    pub fn in_wei(rate: u128) -> Self {
        Self(rate)
    }
}

impl CostEstimate for ConstantRateCost {
    /// It returns the token rate conversion to ETH(wei).
    async fn eth_price(&self, _: &Address) -> Result<u128, EstimateFeeError> {
        Ok(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Token;
    use alloy::primitives::address;

    #[tokio::test]
    async fn constant_cost() {
        let usdt = Token::new(address!("dac17f958d2ee523a2206206994597c13d831ec7"), 6);
        let estimator = ConstantRateCost::in_eth(0.00036796);
        assert_eq!(
            estimator.estimate(&usdt, 3_900_000_000u128).await.unwrap().to::<u128>() * 450_000,
            4_500_000,
        );
    }
}
