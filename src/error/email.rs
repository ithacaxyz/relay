use super::{internal_rpc, invalid_params};
use thiserror::Error;

/// Errors related to emails.
#[derive(Debug, Error)]
pub enum EmailError {
    /// E-mail already verified on at least one account.
    #[error("email already verified")]
    EmailAlreadyVerified,
    /// The verification token was incorrect.
    #[error("invalid verification token")]
    InvalidToken,
    /// The signature was incorrect.
    #[error("invalid token signature")]
    InvalidSignature,
    /// An internal error occurred.
    #[error(transparent)]
    InternalError(#[from] eyre::Error),
}

impl From<EmailError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(err: EmailError) -> Self {
        match err {
            EmailError::EmailAlreadyVerified
            | EmailError::InvalidToken
            | EmailError::InvalidSignature => invalid_params(err.to_string()),
            EmailError::InternalError(..) => internal_rpc(err.to_string()),
        }
    }
}
