use EntryPoint::EntryPointInstance;
use alloy::{
    dyn_abi::Eip712Domain,
    primitives::{Address, FixedBytes, U256, fixed_bytes},
    providers::Provider,
    rpc::types::{
        simulate::{SimBlock, SimulatePayload},
        state::StateOverride,
    },
    sol,
    sol_types::SolValue,
    transports::{TransportErrorKind, TransportResult},
    uint,
};
use serde::{Deserialize, Serialize};
use tracing::debug;

use super::Simulator::SimulatorInstance;
use crate::{
    asset::AssetInfoServiceHandle,
    error::{RelayError, UserOpError},
    types::{AssetDiffs, UserOp},
};

/// The 4-byte selector returned by the entrypoint if there is no error during execution.
pub const ENTRYPOINT_NO_ERROR: FixedBytes<4> = fixed_bytes!("0x00000000");

sol! {
    #[sol(rpc)]
    #[derive(Debug)]
    contract EntryPoint {
        /// Emitted when a UserOp is executed.
        ///
        /// This event is emitted in the `execute` function.
        /// - `incremented` denotes that `nonce`'s sequence has been incremented to invalidate `nonce`,
        /// - `err` denotes the resultant error selector.
        /// If `incremented` is true and `err` is non-zero,
        /// `err` will be stored for retrieval with `nonceStatus`.
        event UserOpExecuted(address indexed eoa, uint256 indexed nonce, bool incremented, bytes4 err);

        /// @dev Unable to perform the payment.
        error PaymentError();

        /// @dev Unable to verify the user op. The user op may be invalid.
        error VerificationError();

        /// Unable to perform the call.
        error CallError();

        /// @dev Unable to perform the verification and the call.
        error VerifiedCallError();

        /// @dev Out of gas to perform the call operation.
        error InsufficientGas();

        /// @dev The order has already been filled.
        error OrderAlreadyFilled();

        /// For returning the gas used and the error from a simulation.
        ///
        /// - `gCombined` is the recommendation for `gCombined` in the UserOp.
        /// - `gUsed` is the amount of gas that has definitely been used by the UserOp.
        ///
        /// If the `err` is non-zero, it means that the simulation with `gExecute` has not resulted in a successful execution.
        struct SimulationResult {
            uint256 gUsed;
            uint256 gCombined;
        }


        /// The simulate execute run has failed. Try passing in more gas to the simulation.
        error SimulateExecuteFailed();

        /// No revert has been encountered.
        error NoRevertEncountered();

        /// A sub UserOp's EOA must be the same as its parent UserOp's eoa.
        error InvalidPreOpEOA();

        /// The sub UserOp cannot be verified to be correct.
        error PreOpVerificationError();

        /// Error calling the sub UserOp's `executionData`.
        error PreOpCallError();

        /// The ID has already been registered.
        error IDOccupied();

        /// Caller is not authorized to modify the ID.
        error InvalidCaller();

        /// Account is already registered in the ID.
        error AlreadyRegistered();

        /// The caller is not authorized to call the function.
        error Unauthorized();

        /// The `newOwner` cannot be the zero address.
        error NewOwnerIsZeroAddress();

        /// The `pendingOwner` does not have a valid handover request.
        error NoHandoverRequest();

        /// Cannot double-initialize.
        error AlreadyInitialized();

        /// The call is from an unauthorized call context.
        error UnauthorizedCallContext();

        /// Unauthorized reentrant call.
        error Reentrancy();

        /// The nonce is invalid.
        error InvalidNonce();

        /// When invalidating a nonce sequence, the new sequence must be larger than the current.
        error NewSequenceMustBeLarger();

        /// Not authorized to perform the call.
        error UnauthorizedCall(bytes32 keyHash, address target, bytes data);

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
        function simulateExecute(bytes calldata encodedUserOp) public payable virtual;

        /// Return current nonce with sequence key.
        function getNonce(address eoa, uint192 seqKey) public view virtual returns (uint256);

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
    entrypoint: EntryPointInstance<P>,
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
    ///
    /// `from` will be used as `msg.sender`, and it should have its balance set to `uint256.max`.
    pub async fn simulate_execute(
        &self,
        simulator: Address,
        op: &UserOp,
        payment_per_gas: U256,
        asset_info_handle: AssetInfoServiceHandle,
    ) -> Result<(AssetDiffs, GasEstimate), RelayError> {
        let simulate_call = SimulatorInstance::new(simulator, self.entrypoint.provider())
            .simulateV1Logs(
                *self.address(),
                true,
                payment_per_gas,
                U256::from(15_000),
                op.abi_encode().into(),
            )
            .into_transaction_request();

        let result = self
            .entrypoint
            .provider()
            .simulate(
                &SimulatePayload::default()
                    .extend(
                        SimBlock::default()
                            .call(simulate_call)
                            .with_state_overrides(self.overrides.clone()),
                    )
                    .with_trace_transfers(),
            )
            .await?
            .pop()
            .and_then(|mut block| block.calls.pop())
            .ok_or_else(|| TransportErrorKind::custom_str("could not simulate call"))?;

        if !result.status {
            debug!(?result, "Unable to simulate user op.");
            return Err(UserOpError::op_revert(result.return_data).into());
        }

        let Ok(gas_estimate) =
            EntryPoint::SimulationResult::abi_decode(&result.return_data).map(|gas| GasEstimate {
                tx: gas.gCombined.to::<u64>() + 25_000,
                op: gas.gCombined.to(),
            })
        else {
            return Err(TransportErrorKind::custom_str(&format!(
                "could not decode op simulation return data: {}",
                result.return_data
            ))
            .into());
        };

        let asset_diffs = asset_info_handle
            .calculate_asset_diff(result.logs.into_iter(), self.entrypoint.provider())
            .await?;

        Ok((asset_diffs, gas_estimate))
    }

    /// Call `EntryPoint.execute` with the provided [`UserOp`].
    pub async fn execute(&self, op: &UserOp) -> Result<(), RelayError> {
        let ret = self
            .entrypoint
            .execute(op.abi_encode().into())
            .call()
            .overrides(self.overrides.clone())
            .await
            .map_err(TransportErrorKind::custom)?;

        if ret != ENTRYPOINT_NO_ERROR {
            Err(UserOpError::op_revert(ret.into()).into())
        } else {
            Ok(())
        }
    }

    /// Get the [`Eip712Domain`] for this entrypoint.
    ///
    /// If `multichain` is `true`, then the chain ID is omitted from the domain.
    pub async fn eip712_domain(&self, multichain: bool) -> TransportResult<Eip712Domain> {
        let domain = self
            .entrypoint
            .eip712Domain()
            .call()
            .overrides(self.overrides.clone())
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

    /// Get the next nonce for the given EOA.
    ///
    /// # Note
    ///
    /// This gets the next nonce for sequence key `0`.
    pub async fn get_nonce(&self, account: Address) -> TransportResult<U256> {
        self.entrypoint
            .getNonce(account, uint!(0_U192))
            .call()
            .overrides(self.overrides.clone())
            .await
            .map_err(TransportErrorKind::custom)
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
