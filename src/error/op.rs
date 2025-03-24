use super::{internal_rpc, invalid_params, rpc_err};
use alloy::{
    primitives::{B256, Bytes},
    rpc::types::error::EthRpcErrorCode,
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
    #[error("op reverted: {revert_reason}")]
    OpRevert {
        /// The error code returned by the entrypoint.
        revert_reason: Bytes,
    },
}

impl From<UserOpError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(err: UserOpError) -> Self {
        match err {
            UserOpError::SimulationError => internal_rpc(err.to_string()),
            UserOpError::InvalidOpDigest { .. } => invalid_params(err.to_string()),
            UserOpError::OpRevert { ref revert_reason } => rpc_err(
                EthRpcErrorCode::ExecutionError.code(),
                err.to_string(),
                Some(revert_reason.clone()),
            ),
        }
    }
}
