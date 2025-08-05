use super::{internal_rpc, invalid_params};
use alloy::primitives::{Address, ChainId, U256};
use thiserror::Error;

/// Errors related to quotes.
#[derive(Debug, Error)]
pub enum QuoteError {
    /// The quote expired.
    #[error("quote expired")]
    QuoteExpired,
    /// The quote was not found.
    #[error("expected quote was not found")]
    QuoteNotFound,
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
    /// The payment amount in the intent did not match the amount in the quote.
    #[error("invalid fee amount, expected {expected}, got {got}")]
    InvalidFeeAmount {
        /// The amount expected.
        expected: U256,
        /// The amount in the [`Intent`].
        got: U256,
    },
    /// Number of intents in quotes did not match the number of providers.
    #[error("invalid number of intents, expected {expected}, got {got}")]
    InvalidNumberOfIntents {
        /// Number of expected intents.
        expected: usize,
        /// Number of available intents.
        got: usize,
    },
    /// Missing required funds in the request.
    #[error("missing required funds")]
    MissingRequiredFunds,
    /// Multichain functionality is disabled.
    #[error("multichain functionality is disabled: interop service not configured")]
    MultichainDisabled,
    /// Insufficient balance to pay for the transaction.
    #[error("insufficient balance: required {required}, available {available}, deficit {deficit}")]
    InsufficientBalance {
        /// The required amount for the transaction.
        required: U256,
        /// The available balance in the fee token.
        available: U256,
        /// The deficit amount (required - available).
        deficit: U256,
    },
}

impl From<QuoteError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(err: QuoteError) -> Self {
        match err {
            QuoteError::QuoteExpired
            | QuoteError::QuoteNotFound
            | QuoteError::InvalidQuoteSignature
            | QuoteError::UnsupportedFeeToken(..)
            | QuoteError::InvalidNumberOfIntents { .. }
            | QuoteError::InvalidFeeAmount { .. }
            | QuoteError::MissingRequiredFunds
            | QuoteError::InsufficientBalance { .. }
            | QuoteError::MultichainDisabled => invalid_params(err.to_string()),
            QuoteError::UnavailablePrice(..) | QuoteError::UnavailablePriceFeed(_) => {
                internal_rpc(err.to_string())
            }
        }
    }
}
