//! Tokens cost estimators.

mod constant;
pub use constant::ConstantRateCost;

mod coingecko;

use crate::{error::EstimateFeeError, types::Token};
use alloy::primitives::{Address, U256};

/// A trait for estimating the cost per smallest unit in various tokens.
pub trait CostEstimate: Send + Sync + 'static {
    /// Returns a token price per gas estimation.
    fn estimate(
        &self,
        token: &Token,
        gas_price: u128,
    ) -> impl std::future::Future<Output = Result<U256, EstimateFeeError>> + Send {
        async move {
            let eth_wei_price = self.eth_price(&token.address).await?;
            Ok((U256::from(gas_price) * U256::from(10u128.pow(token.decimals as u32)))
                / U256::from(eth_wei_price))
        }
    }

    /// Returns the token rate conversion into ETH(wei).
    fn eth_price(
        &self,
        payment_token: &Address,
    ) -> impl std::future::Future<Output = Result<u128, EstimateFeeError>> + Send;
}
