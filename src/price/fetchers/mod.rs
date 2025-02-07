mod coingecko;
pub use coingecko::*;

/// List of supported coin fetchers.
#[derive(Debug, Eq, PartialEq, Hash)]
pub enum PriceFetcher {
    /// CoinGecko.
    CoinGecko,
}
