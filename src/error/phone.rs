//! Phone verification-related errors.

use super::{internal_rpc, invalid_params};
use thiserror::Error;

/// Errors that can occur during phone verification.
#[derive(Debug, Error)]
pub enum PhoneError {
    /// Phone already verified on at least one account.
    #[error("phone already verified")]
    PhoneAlreadyVerified,
    /// The verification code was incorrect.
    #[error("invalid verification code")]
    InvalidCode,
    /// Too many verification attempts.
    #[error("too many verification attempts")]
    TooManyAttempts,
    /// Rate limit exceeded.
    #[error("rate limit exceeded")]
    RateLimitExceeded,
    /// Invalid phone number format.
    #[error("invalid phone number")]
    InvalidPhoneNumber,
    /// An internal error occurred.
    #[error(transparent)]
    InternalError(#[from] eyre::Error),
}

impl From<PhoneError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(err: PhoneError) -> Self {
        match err {
            PhoneError::PhoneAlreadyVerified
            | PhoneError::InvalidCode
            | PhoneError::TooManyAttempts
            | PhoneError::RateLimitExceeded
            | PhoneError::InvalidPhoneNumber => invalid_params(err.to_string()),
            PhoneError::InternalError(..) => internal_rpc(err.to_string()),
        }
    }
}
