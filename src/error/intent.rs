use super::{MerkleError, internal_rpc, invalid_params, rpc_err};
use crate::{
    error::ContractErrors,
    types::{IthacaAccount::IthacaAccountErrors, OrchestratorContract::OrchestratorContractErrors},
};
use alloy::{
    primitives::{Address, B256, Bytes},
    rpc::types::error::EthRpcErrorCode,
    sol_types::SolInterface,
};
use thiserror::Error;

/// Errors related to intents.
#[derive(Debug, Error)]
pub enum IntentError {
    /// The intent could not be simulated without a sender.
    #[error("intent creation requires a sender.")]
    MissingSender,
    /// The intent could not be simulated without a key.
    #[error("intent creation requires a signing key.")]
    MissingKey,
    /// The intent could not be simulated.
    #[error("the intent could not be simulated")]
    SimulationError,
    /// The precall can only contain account management calls.
    #[error("the precall can only contain account management calls.")]
    UnallowedPreCall,
    /// The quote was signed for a different intent.
    #[error("invalid intent digest, expected {expected}, got {got}")]
    InvalidIntentDigest {
        /// The digest expected.
        expected: B256,
        /// The digest of the [`Intent`].
        got: B256,
    },
    /// The intent reverted when trying transaction.
    #[error(transparent)]
    IntentRevert(#[from] IntentRevert),
    /// The intent could not be simulated since the orchestrator is paused.
    #[error("the orchestrator is paused")]
    PausedOrchestrator,
    /// Invalid initialization precall signature.
    #[error("invalid precall recovered address, expected {expected}, got {got:?}")]
    InvalidPreCallRecovery {
        /// The address expected.
        expected: Address,
        /// The address recovered item.
        got: Option<Address>,
    },
    /// Merkle tree operation error.
    #[error(transparent)]
    Merkle(#[from] MerkleError),
    /// Fee signature is required when a payer is specified.
    #[error("fee signature is required when a payer is specified")]
    MissingFeeSignature,
}

impl IntentError {
    /// Creates a new [`IntentError::IntentRevert`] error.
    pub fn intent_revert(revert_reason: Bytes) -> Self {
        Self::IntentRevert(IntentRevert::new(revert_reason))
    }
}

impl From<IntentError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(err: IntentError) -> Self {
        match err {
            IntentError::PausedOrchestrator | IntentError::SimulationError => {
                internal_rpc(err.to_string())
            }
            IntentError::MissingKey
            | IntentError::MissingSender
            | IntentError::UnallowedPreCall
            | IntentError::InvalidPreCallRecovery { .. }
            | IntentError::InvalidIntentDigest { .. }
            | IntentError::MissingFeeSignature => invalid_params(err.to_string()),
            IntentError::Merkle(_) => internal_rpc(err.to_string()),
            IntentError::IntentRevert(err) => err.into(),
        }
    }
}

/// An on-chain revert of a intent.
#[derive(Debug, Error)]
pub struct IntentRevert {
    /// The returned revert reason bytes.
    revert_reason: Bytes,
    /// Decoded revert reason.
    decoded_error: Option<String>,
}

impl std::fmt::Display for IntentRevert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { revert_reason, decoded_error } = self;
        write!(f, "intent reverted:")?;
        if let Some(err) = decoded_error {
            write!(f, " {err}")
        } else {
            write!(f, " {revert_reason}")
        }
    }
}

impl IntentRevert {
    /// Creates a new instance of [`IntentRevert`]. Attempts to decode
    /// [`OrchestratorContractErrors`] and[`IthacaAccountErrors`] .
    pub fn new(revert_reason: Bytes) -> Self {
        Self {
            decoded_error: OrchestratorContractErrors::abi_decode(&revert_reason)
                .ok()
                .map(|err| format!("{err:?}"))
                .or_else(|| {
                    IthacaAccountErrors::abi_decode(&revert_reason)
                        .ok()
                        .map(|err| format!("{err:?}"))
                })
                .or_else(|| {
                    ContractErrors::ContractErrorsErrors::abi_decode(&revert_reason)
                        .ok()
                        .map(|err| format!("{err:?}"))
                }),
            revert_reason,
        }
    }
}

impl From<IntentRevert> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(value: IntentRevert) -> Self {
        let IntentRevert { revert_reason, decoded_error } = value;
        rpc_err(
            EthRpcErrorCode::ExecutionError.code(),
            decoded_error.unwrap_or_else(|| revert_reason.to_string()),
            Some(revert_reason.clone()),
        )
    }
}
