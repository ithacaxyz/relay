use super::invalid_params;
use crate::types::PREPAccount;
use alloy::primitives::Address;
use thiserror::Error;

/// Errors related to 7702 authorizations.
#[derive(Debug, Error)]
pub enum AuthError {
    /// Invalid authorization item address.
    #[error("invalid auth item, expected {expected}, got {got}")]
    InvalidAuthAddress {
        /// The address expected.
        expected: Address,
        /// The address in the authorization item.
        got: Address,
    },
    /// The provided EIP-7702 auth item is not chain agnostic.
    #[error("the auth item is not chain agnostic")]
    AuthItemNotChainAgnostic,
    /// The provided EIP-7702 auth item has an invalid nonce.
    #[error("invalid auth item nonce, expected {expected}, got {got}")]
    AuthItemInvalidNonce {
        /// The nonce expected.
        expected: u64,
        /// The nonce in the authorization item.
        got: u64,
    },
    /// The quote was signed for a different authorization item.
    #[error("invalid authorization item, expected {expected:?}, got {got:?}")]
    InvalidAuthItem {
        /// The expected item.
        expected: Option<Address>,
        /// The item in the request.
        got: Option<Address>,
    },
    /// The `eoa` field of the provided `UserOp` is not an EIP-7702 delegated account.
    #[error("eoa not delegated: {0}")]
    EoaNotDelegated(Address),
    /// The provided PREPAccount is not valid.
    #[error("invalid PREPAccount item: {0:?}")]
    InvalidPrep(PREPAccount),
}

impl From<AuthError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(err: AuthError) -> Self {
        match err {
            AuthError::InvalidAuthAddress { .. }
            | AuthError::AuthItemNotChainAgnostic
            | AuthError::AuthItemInvalidNonce { .. }
            | AuthError::InvalidAuthItem { .. }
            | AuthError::InvalidPrep { .. }
            | AuthError::EoaNotDelegated(..) => invalid_params(err.to_string()),
        }
    }
}

impl AuthError {
    /// Converts the error to a boxed [`AuthError`].
    pub fn boxed(self) -> Box<Self> {
        Box::new(self)
    }
}
