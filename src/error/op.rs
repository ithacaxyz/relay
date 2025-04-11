use super::{internal_rpc, invalid_params, rpc_err};
use crate::types::{Delegation::DelegationErrors, EntryPoint::EntryPointErrors};
use alloy::{
    primitives::{B256, Bytes},
    rpc::types::error::EthRpcErrorCode,
    sol_types::SolInterface,
};
use thiserror::Error;

/// Errors related to user ops.
#[derive(Debug, Error)]
pub enum UserOpError {
    /// The userop could not be simulated.
    #[error("the op could not be simulated")]
    SimulationError,
    /// The quote was signed for a different userop.
    #[error("invalid op digest, expected {expected}, got {got}")]
    InvalidOpDigest {
        /// The digest expected.
        expected: B256,
        /// The digest of the [`UserOp`].
        got: B256,
    },
    /// The userop reverted when trying transaction.
    #[error(transparent)]
    OpRevert(#[from] OpRevert),
}

impl UserOpError {
    /// Creates a new [`UserOpError::OpRevert`] error.
    pub fn op_revert(revert_reason: Bytes) -> Self {
        Self::OpRevert(OpRevert::new(revert_reason))
    }
}

impl From<UserOpError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(err: UserOpError) -> Self {
        match err {
            UserOpError::SimulationError => internal_rpc(err.to_string()),
            UserOpError::InvalidOpDigest { .. } => invalid_params(err.to_string()),
            UserOpError::OpRevert(err) => err.into(),
        }
    }
}

/// An on-chain revert of a userop.
#[derive(Debug, Error)]
pub struct OpRevert {
    /// The returned revert reason bytes.
    revert_reason: Bytes,
    /// Decoded revert reason.
    decoded_error: Option<String>,
}

impl std::fmt::Display for OpRevert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { revert_reason, decoded_error } = self;
        write!(f, "op reverted:")?;
        if let Some(err) = decoded_error {
            write!(f, " {err}")
        } else {
            write!(f, " {revert_reason}")
        }
    }
}

impl OpRevert {
    /// Creates a new instance of [`OpRevert`]. Attempts to decode [`EntryPointErrors`]
    /// and[`DelegationErrors`] .
    pub fn new(revert_reason: Bytes) -> Self {
        Self {
            decoded_error: EntryPointErrors::abi_decode(&revert_reason)
                .ok()
                .map(|err| format!("{err:?}"))
                .or_else(|| {
                    DelegationErrors::abi_decode(&revert_reason).ok().map(|err| format!("{err:?}"))
                }),
            revert_reason,
        }
    }
}

impl From<OpRevert> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(value: OpRevert) -> Self {
        let OpRevert { revert_reason, decoded_error } = value;
        rpc_err(
            EthRpcErrorCode::ExecutionError.code(),
            decoded_error.unwrap_or_else(|| revert_reason.to_string()),
            Some(revert_reason.clone()),
        )
    }
}
