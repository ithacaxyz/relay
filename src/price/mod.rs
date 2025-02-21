//! Price oracle and fetchers.

mod fetchers;
pub use fetchers::*;

mod oracle;
pub use oracle::PriceOracle;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CoinKind, CoinPair, CoinRegistry};
    use std::{sync::Arc, time::Duration};
    use tokio::time::sleep;

    #[ignore] // requires GECKO_API
    #[tokio::test]
    async fn coingecko() {
        let oracle = PriceOracle::new();
        oracle.spawn_fetcher(
            Arc::new(CoinRegistry::default()),
            PriceFetcher::CoinGecko,
            &[
                CoinPair { from: CoinKind::USDT, to: CoinKind::ETH },
                CoinPair { from: CoinKind::USDC, to: CoinKind::ETH },
            ],
        );

        // Allow coingecko to fetch prices
        sleep(Duration::from_millis(500)).await;

        oracle.eth_price(CoinKind::USDT).await.unwrap();
        oracle.eth_price(CoinKind::USDC).await.unwrap();
    }
}
