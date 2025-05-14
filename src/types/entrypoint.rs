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
};
use tracing::debug;

use super::{KeyType, SimulationResult, Simulator::SimulatorInstance};
use crate::{
    asset::AssetInfoServiceHandle,
    constants::P256_GAS_BUFFER,
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

        /// The entrypoint is paused.
        error Paused();

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


        /// Returns the implementation of the EOA.
        /// If the EOA's delegation's is not valid EIP7702Proxy (via bytecode check), returns `address(0)`.
        ///
        /// This function is provided as a public helper for easier integration.
        function delegationImplementationOf(address eoa) public view virtual returns (address result);

        /// The pause flag.
        function pauseFlag() public returns (uint256);

        /// Can be used to pause/unpause the contract, in case of emergencies.
        function pause(bool isPause) public;

        /// Returns the pause authority and the last pause timestamp.
        function getPauseConfig() public view virtual returns (address, uint40);
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

    /// Call `Simulator.simulateV1Logs` with the provided [`UserOp`].
    ///
    /// `simulator` contract address should have its balance set to `uint256.max`.
    pub async fn simulate_execute(
        &self,
        simulator: Address,
        op: &UserOp,
        key_type: KeyType,
        payment_per_gas: U256,
        asset_info_handle: AssetInfoServiceHandle,
    ) -> Result<(AssetDiffs, SimulationResult), RelayError> {
        // Allows to account for gas variation in P256 sig verification.
        let gas_validation_offset =
            if key_type.is_secp256k1() { U256::ZERO } else { P256_GAS_BUFFER };

        let simulate_block = SimBlock::default()
            .call(
                SimulatorInstance::new(simulator, self.entrypoint.provider())
                    .simulateV1Logs(
                        *self.address(),
                        true,
                        payment_per_gas,
                        U256::from(11_000),
                        gas_validation_offset,
                        op.abi_encode().into(),
                    )
                    .into_transaction_request(),
            )
            .with_state_overrides(self.overrides.clone());

        let result = self
            .entrypoint
            .provider()
            .simulate(
                &SimulatePayload::default().extend(simulate_block.clone()).with_trace_transfers(),
            )
            .await?
            .pop()
            .and_then(|mut block| block.calls.pop())
            .ok_or_else(|| TransportErrorKind::custom_str("could not simulate call"))?;

        if !result.status {
            debug!(?result, ?simulate_block, "Unable to simulate user op.");

            if self.is_paused().await? {
                return Err(UserOpError::PausedEntrypoint.into());
            }

            return Err(UserOpError::op_revert(result.return_data).into());
        }

        let Ok(simulation_result) = SimulationResult::abi_decode(&result.return_data) else {
            return Err(TransportErrorKind::custom_str(&format!(
                "could not decode op simulation return data: {}",
                result.return_data
            ))
            .into());
        };

        let asset_diffs = asset_info_handle
            .calculate_asset_diff(
                simulate_block,
                result.logs.into_iter(),
                self.entrypoint.provider(),
            )
            .await?;

        Ok((asset_diffs, simulation_result))
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

    /// Whether the entrypoint has been paused.
    pub async fn is_paused(&self) -> TransportResult<bool> {
        Ok(self
            .entrypoint
            .pauseFlag()
            .call()
            .overrides(self.overrides.clone())
            .await
            .map_err(TransportErrorKind::custom)?
            == U256::ONE)
    }
}
