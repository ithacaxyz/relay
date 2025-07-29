mod coingecko;
pub use coingecko::*;

mod defillama;
pub use defillama::{CoinData, DeFiLlamaClient, PriceResponse};

/// List of supported coin fetchers.
#[derive(Debug, Eq, PartialEq, Hash)]
pub enum PriceFetcher {
    /// CoinGecko.
    CoinGecko,
}
