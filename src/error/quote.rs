use super::{internal_rpc, invalid_params};
use alloy::primitives::{Address, ChainId, U256};
use thiserror::Error;

/// Errors related to quotes.
#[derive(Debug, Error)]
pub enum QuoteError {
    /// The quote expired.
    #[error("quote expired")]
    QuoteExpired,
    /// The provided quote was not signed by the relay.
    #[error("invalid quote signer")]
    InvalidQuoteSignature,
    /// The provided fee token is not supported.
    #[error("fee token not supported: {0}")]
    UnsupportedFeeToken(Address),
    /// The price for fee token is not available.
    #[error("fee token price not currently available: {0}")]
    UnavailablePrice(Address),
    /// The chain price feed is not available.
    #[error("price feed is currently not available on chain: {0}")]
    UnavailablePriceFeed(ChainId),
    /// The payment amount in the userop did not match the amount in the quote.
    #[error("invalid fee amount, expected {expected}, got {got}")]
    InvalidFeeAmount {
        /// The amount expected.
        expected: U256,
        /// The amount in the [`UserOp`].
        got: U256,
    },
}

impl From<QuoteError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(err: QuoteError) -> Self {
        match err {
            QuoteError::QuoteExpired
            | QuoteError::InvalidQuoteSignature
            | QuoteError::UnsupportedFeeToken(..)
            | QuoteError::InvalidFeeAmount { .. } => invalid_params(err.to_string()),
            QuoteError::UnavailablePrice(..) | QuoteError::UnavailablePriceFeed(_) => {
                internal_rpc(err.to_string())
            }
        }
    }
}
