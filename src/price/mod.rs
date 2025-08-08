//! Price oracle and fetchers.

mod fetchers;
pub use fetchers::*;

mod metrics;
mod oracle;
pub use oracle::{PriceOracle, PriceOracleConfig};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CoinKind;
    use std::time::Duration;
    use tokio::time::sleep;

    #[ignore] // requires GECKO_API
    #[tokio::test]
    async fn coingecko() {
        let oracle = PriceOracle::new(Default::default());
        oracle.spawn_fetcher(PriceFetcher::CoinGecko);

        // Allow coingecko to fetch prices
        sleep(Duration::from_millis(500)).await;

        oracle.eth_price(CoinKind::USDT).await.unwrap();
        oracle.eth_price(CoinKind::USDC).await.unwrap();
    }
}
