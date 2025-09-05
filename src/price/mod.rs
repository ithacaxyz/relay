//! Price oracle and fetchers.

mod fetchers;
pub use fetchers::*;

mod metrics;
mod oracle;
pub use oracle::{PriceOracle, PriceOracleConfig};

use alloy::primitives::{U256, U512};

/// Calculate the USD value of a token amount given its USD price and decimals.
///
/// This converts an amount in the smallest unit (e.g., wei) to its USD value
/// based on the USD price per whole token (e.g., USD price per ETH).
///
/// # Returns
/// The total USD value as f64
pub fn calculate_usd_value(token_amount: U256, usd_price: f64, decimals: u8) -> f64 {
    let result = U512::from(token_amount).saturating_mul(U512::from(usd_price * 1e18))
        / U512::from(10u128.pow(decimals as u32));
    result.to::<u128>() as f64 / 1e18
}

#[cfg(test)]
mod tests {
    use crate::types::AssetUid;

    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;

    #[ignore] // requires GECKO_API
    #[tokio::test]
    async fn coingecko() {
        let oracle = PriceOracle::new(Default::default());
        oracle.spawn_fetcher(PriceFetcher::CoinGecko, &Default::default());

        // Allow coingecko to fetch prices
        sleep(Duration::from_millis(500)).await;

        oracle
            .native_conversion_rate(
                AssetUid::new("usd-coin".into()),
                AssetUid::new("ethereum".into()),
            )
            .await
            .unwrap();
        oracle
            .native_conversion_rate(
                AssetUid::new("tether".into()),
                AssetUid::new("ethereum".into()),
            )
            .await
            .unwrap();
    }
}
