//! Tokens cost estimators.

mod constant;
pub use constant::ConstantRateCost;

mod coingecko;
pub use coingecko::CoinGecko;

use crate::{error::EstimateFeeError, types::Token};
use alloy::primitives::{Address, U256};
use jsonrpsee::core::async_trait;
use std::fmt::Debug;

/// A trait for estimating the cost per smallest unit in various tokens.
#[async_trait]
pub trait CostEstimate: Debug + Sync + Send + 'static {
    /// Returns a token price per gas estimation.
    async fn estimate(&self, token: &Token, gas_price: u128) -> Result<U256, EstimateFeeError> {
        let eth_wei_price = self.eth_price(&token.address).await?;
        Ok((U256::from(gas_price) * U256::from(10u128.pow(token.decimals as u32)))
            / U256::from(eth_wei_price))
    }

    /// Returns the conversion rate for the token to native tokens (in wei).
    async fn eth_price(&self, payment_token: &Address) -> Result<u128, EstimateFeeError>;
}
