pub mod price;
pub use price::*;

/// Background services used by the relay.
#[derive(Debug)]
pub struct RelayServives {
    /// Price oracle service.
    pub price_oracle: PriceOracle,
    /// Transaction service.
    pub transaction: crate::transactions::TransactionService
}
