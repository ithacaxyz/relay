use alloy::{
    dyn_abi::Eip712Domain,
    primitives::{fixed_bytes, Address, Bytes, FixedBytes, U256},
    providers::Provider,
    rpc::types::state::StateOverride,
    sol,
    sol_types::{SolError, SolValue},
    transports::{TransportErrorKind, TransportResult},
};
use EntryPoint::EntryPointInstance;

use crate::error::CallError;

use super::UserOp;

/// The 4-byte selector returned by the entrypoint if there is no error during execution.
pub const ENTRYPOINT_NO_ERROR: FixedBytes<4> = fixed_bytes!("00000000");

sol! {
    #[sol(rpc)]
    contract EntryPoint {
        /// For returning the gas used and the error from a simulation.
        #[derive(Debug)]
        error SimulationResult(uint256 gUsed, bytes4 err);

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
        ///
        /// An error selector of 0 means the call did not revert.
        function simulateExecute(bytes calldata encodedUserOp) public payable virtual;

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

    /// Call `EntryPoint.simulateExecute` with the provided [`UserOp`].
    pub async fn simulate_execute(&self, op: &UserOp) -> Result<U256, CallError> {
        let ret = self
            .entrypoint
            .simulateExecute(op.abi_encode().into())
            .call()
            .overrides(&self.overrides)
            .await;

        match ret {
            Err(alloy::contract::Error::TransportError(err)) => {
                let revert_data = err.as_error_resp().and_then(|res| res.as_revert_data());

                if let Ok(result) = EntryPoint::SimulationResult::abi_decode(
                    revert_data.as_deref().unwrap_or(&Bytes::default()),
                    false,
                ) {
                    if result.err != ENTRYPOINT_NO_ERROR {
                        Err(CallError::OpRevert { revert_reason: result.err.into() })
                    } else {
                        Ok(result.gUsed)
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
}
