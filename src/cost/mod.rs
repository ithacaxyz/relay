//! Tokens cost estimators.

mod constant;
pub use constant::ConstantRateCost;

mod coingecko;

use crate::error::EstimateFeeError;
use alloy::{
    primitives::{Address, U256},
    providers::utils::Eip1559Estimation,
};

/// A trait for estimating the cost of relaying a transaction in various tokens.
pub trait CostEstimate: Send + Sync + 'static {
    /// Given a gas estimate, it returns a price with 18 decimals. If token is `None`, it
    /// returns its price in ETH (wei) instead.
    fn estimate(
        &self,
        gas_estimate: u64,
        native_fee_estimate: Eip1559Estimation,
        token: Option<Address>,
    ) -> impl std::future::Future<Output = Result<U256, EstimateFeeError>> + Send;
}
