//! Price oracle and fetchers.

mod fetchers;
pub use fetchers::*;

mod metrics;
mod oracle;
pub use oracle::{PriceOracle, PriceOracleConfig};

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
