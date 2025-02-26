use EntryPoint::EntryPointInstance;
use alloy::{
    dyn_abi::Eip712Domain,
    primitives::{Address, Bytes, FixedBytes, U256, fixed_bytes},
    providers::Provider,
    rpc::types::state::StateOverride,
    sol,
    sol_types::{SolError, SolValue},
    transports::{TransportErrorKind, TransportResult},
};
use serde::{Deserialize, Serialize};

use crate::error::CallError;

use super::UserOp;

/// The 4-byte selector returned by the entrypoint if there is no error during execution.
pub const ENTRYPOINT_NO_ERROR: FixedBytes<4> = fixed_bytes!("0x00000000");

sol! {
    #[sol(rpc)]
    contract EntryPoint {
        /// For returning the gas used and the error from a simulation.
        ///
        /// - `gExecute` is the recommended amount of gas to use for the transaction when calling `execute`.
        /// - `gCombined` is the recommendation for `gCombined` in the UserOp.
        /// - `gUsed` is the amount of gas that has definitely been used by the UserOp.
        ///
        /// If the `err` is non-zero, it means that the simulation with `gExecute` has not resulted in a successful execution.
        #[derive(Debug)]
        error SimulationResult2(uint256 gExecute, uint256 gCombined, uint256 gUsed, bytes4 err);

        /// Executes a single encoded user operation.
        ///
        /// `encodedUserOp` is given by `abi.encode(userOp)`, where `userOp` is a struct of type `UserOp`.
        /// If sufficient gas is provided, returns an error selector that is non-zero
        /// if there is an error during the payment, verification, and call execution.
        function execute(bytes calldata encodedUserOp)
            public
            payable
            virtual
            nonReentrant
            returns (bytes4 err);

        /// Simulates an execution and reverts with the amount of gas used, and the error selector.
        function simulateExecute2(bytes calldata encodedUserOp) public payable virtual;

        /// Returns the current sequence for the `seqKey` in nonce (i.e. upper 192 bits). Also returns the err for that nonce.
        ///
        /// If `seq > uint64(nonce)`, it means that `nonce` is invalidated.
        /// Otherwise, it means `nonce` might still be able to be used.
        function nonceStatus(address eoa, uint256 nonce)
            public
            view
            virtual
            returns (uint64 seq, bytes4 err);

        /// Returns the EIP712 domain of the entrypoint.
        ///
        /// See: https://eips.ethereum.org/EIPS/eip-5267
        function eip712Domain()
            public
            view
            virtual
            returns (
                bytes1 fields,
                string memory name,
                string memory version,
                uint256 chainId,
                address verifyingContract,
                bytes32 salt,
                uint256[] memory extensions
            );
    }
}

/// A Porto entrypoint.
#[derive(Debug)]
pub struct Entry<P: Provider> {
    entrypoint: EntryPointInstance<(), P>,
    overrides: StateOverride,
}

impl<P: Provider> Entry<P> {
    /// Create a new instance of [`Entry`].
    pub fn new(address: Address, provider: P) -> Self {
        Self {
            entrypoint: EntryPointInstance::new(address, provider),
            overrides: StateOverride::default(),
        }
    }

    /// Get the address of the entrypoint.
    pub fn address(&self) -> &Address {
        self.entrypoint.address()
    }

    /// Sets overrides for all calls on this entrypoint.
    pub fn with_overrides(mut self, overrides: StateOverride) -> Self {
        self.overrides = overrides;
        self
    }

    /// Call `EntryPoint.simulateExecute` with the provided [`UserOp`].
    pub async fn simulate_execute(&self, op: &UserOp) -> Result<GasEstimate, CallError> {
        let ret = self
            .entrypoint
            .simulateExecute2(op.abi_encode().into())
            .call()
            .overrides(&self.overrides)
            .await;

        match ret {
            Err(alloy::contract::Error::TransportError(err)) => {
                let revert_data = err.as_error_resp().and_then(|res| res.as_revert_data());

                if let Ok(result) = EntryPoint::SimulationResult2::abi_decode(
                    revert_data.as_deref().unwrap_or(&Bytes::default()),
                    false,
                ) {
                    if result.err != ENTRYPOINT_NO_ERROR {
                        Err(CallError::OpRevert { revert_reason: result.err.into() })
                    } else {
                        // todo: sanitize this as a malicious contract can make us panic
                        Ok(GasEstimate { tx: result.gExecute.to(), op: result.gCombined.to() })
                    }
                } else if let Some(data) = revert_data {
                    Err(CallError::OpRevert { revert_reason: data })
                } else {
                    Err(TransportErrorKind::custom_str("could not simulate op").into())
                }
            }
            Err(err) => Err(TransportErrorKind::custom(err).into()),
            Ok(_) => Err(TransportErrorKind::custom_str("could not simulate op").into()),
        }
    }

    /// Call `EntryPoint.execute` with the provided [`UserOp`].
    pub async fn execute(&self, op: &UserOp) -> Result<(), CallError> {
        let ret = self
            .entrypoint
            .execute(op.abi_encode().into())
            .call()
            .overrides(&self.overrides)
            .await
            .map_err(TransportErrorKind::custom)?;

        if ret.err != ENTRYPOINT_NO_ERROR {
            Err(CallError::OpRevert { revert_reason: ret.err.into() })
        } else {
            Ok(())
        }
    }

    /// Get status of the given nonce.
    ///
    /// Returns the current sequence for the sequence key in the given nonce, as well as the status
    /// of the call.
    ///
    /// If the status is not equal to `ENTRYPOINT_NO_ERROR`, it means that the call failed.
    ///
    /// If `seq > uint64(nonce)`, it means that `nonce` is invalidated.
    /// Otherwise, it means `nonce` might still be able to be used.
    pub async fn nonce_status(
        &self,
        account: Address,
        nonce: U256,
    ) -> TransportResult<(u64, FixedBytes<4>)> {
        let status = self
            .entrypoint
            .nonceStatus(account, nonce)
            .call()
            .overrides(&self.overrides)
            .await
            .map_err(TransportErrorKind::custom)?;

        Ok((status.seq, status.err))
    }

    /// Get the [`Eip712Domain`] for this entrypoint.
    ///
    /// If `multichain` is `true`, then the chain ID is omitted from the domain.
    pub async fn eip712_domain(&self, multichain: bool) -> TransportResult<Eip712Domain> {
        let domain = self
            .entrypoint
            .eip712Domain()
            .call()
            .overrides(&self.overrides)
            .await
            .map_err(TransportErrorKind::custom)?;

        Ok(Eip712Domain::new(
            Some(domain.name.into()),
            Some(domain.version.into()),
            (!multichain).then_some(domain.chainId),
            Some(domain.verifyingContract),
            None,
        ))
    }
}

/// A gas estimate result for a [`UserOp`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasEstimate {
    /// The recommended gas limit for the transaction.
    #[serde(with = "alloy::serde::quantity")]
    pub tx: u64,
    /// The recommended gas limit for the [`UserOp`].
    #[serde(with = "alloy::serde::quantity")]
    pub op: u64,
}
