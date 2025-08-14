use OrchestratorContract::OrchestratorContractInstance;
use alloy::{
    dyn_abi::Eip712Domain,
    primitives::{Address, FixedBytes, U256, fixed_bytes},
    providers::Provider,
    rpc::types::{TransactionReceipt, state::StateOverride},
    sol,
    sol_types::SolValue,
    transports::{TransportErrorKind, TransportResult},
};
use tracing::debug;

use super::{GasResults, simulator::SimulatorContract};
use crate::{
    asset::AssetInfoServiceHandle,
    error::{IntentError, RelayError},
    types::{AssetDiffs, Intent, OrchestratorContract::IntentExecuted},
};

/// The 4-byte selector returned by the orchestrator if there is no error during execution.
pub const ORCHESTRATOR_NO_ERROR: FixedBytes<4> = fixed_bytes!("0x00000000");

sol! {
    #[sol(rpc)]
    #[derive(Debug)]
    contract OrchestratorContract {
        /// Emitted when a Intent is executed.
        ///
        /// This event is emitted in the `execute` function.
        /// - `incremented` denotes that `nonce`'s sequence has been incremented to invalidate `nonce`,
        /// - `err` denotes the resultant error selector.
        /// If `incremented` is true and `err` is non-zero,
        /// `err` will be stored for retrieval with `nonceStatus`.
        event IntentExecuted(address indexed eoa, uint256 indexed nonce, bool incremented, bytes4 err);

        /// @dev Unable to perform the payment.
        error PaymentError();

        /// @dev Unable to verify the intent. The intent may be invalid.
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

        /// A PreCall's EOA must be the same as its parent Intent's.
        error InvalidPreCallEOA();

        /// The PreCall cannot be verified to be correct.
        error PreCallVerificationError();

        /// Error calling the sub Intent's `executionData`.
        error PreCallError();

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

        /// The orchestrator is paused.
        error Paused();

        /// Not authorized to perform the call.
        error UnauthorizedCall(bytes32 keyHash, address target, bytes data);

        /// Executes a single encoded intenteration.
        ///
        /// `encodedIntent` is given by `abi.encode(intent)`, where `intent` is a struct of type `Intent`.
        /// If sufficient gas is provided, returns an error selector that is non-zero
        /// if there is an error during the payment, verification, and call execution.
        function execute(bytes calldata encodedIntent)
            public
            payable
            virtual
            nonReentrant
            returns (bytes4 err);

        /// Returns the EIP712 domain of the orchestrator.
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
        function accountImplementationOf(address eoa) public view virtual returns (address result);

        /// The pause flag.
        function pauseFlag() public returns (uint256);

        /// Can be used to pause/unpause the contract, in case of emergencies.
        function pause(bool isPause) public;

        /// Returns the pause authority and the last pause timestamp.
        function getPauseConfig() public view virtual returns (address, uint40);
    }
}

/// The orchestrator.
#[derive(Debug)]
pub struct Orchestrator<P: Provider> {
    orchestrator: OrchestratorContractInstance<P>,
    overrides: StateOverride,
}

impl<P: Provider> Orchestrator<P> {
    /// Create a new instance of [`Entry`].
    pub fn new(address: Address, provider: P) -> Self {
        Self {
            orchestrator: OrchestratorContractInstance::new(address, provider),
            overrides: StateOverride::default(),
        }
    }

    /// Get the address of the orchestrator.
    pub fn address(&self) -> &Address {
        self.orchestrator.address()
    }

    /// Sets overrides for all calls on this orchestrator.
    pub fn with_overrides(mut self, overrides: StateOverride) -> Self {
        self.overrides = overrides;
        self
    }

    /// Call `Simulator.simulateV1Logs` with the provided [`Intent`].
    ///
    /// `simulator` contract address should have its balance set to `uint256.max`.
    pub async fn simulate_execute(
        &self,
        mock_from: Address,
        simulator: Address,
        intent: &Intent,
        asset_info_handle: AssetInfoServiceHandle,
        gas_validation_offset: U256,
    ) -> Result<(AssetDiffs, GasResults), RelayError> {
        let result =
            SimulatorContract::new(simulator, self.orchestrator.provider(), self.overrides.clone())
                .simulate(*self.address(), mock_from, intent.abi_encode(), gas_validation_offset)
                .await;

        // If simulation failed, check if orchestrator is paused
        if result.is_err() && self.is_paused().await? {
            return Err(IntentError::PausedOrchestrator.into());
        }
        let result = result?;
        let chain_id = self.orchestrator.provider().get_chain_id().await?;

        debug!(chain_id, block_number = %result.block_number, account = %intent.eoa, nonce = %intent.nonce, "simulation executed");

        // calculate asset diffs using the transaction request from simulation
        let mut asset_diffs = asset_info_handle
            .calculate_asset_diff(
                &result.tx_request,
                self.overrides.clone(),
                result.logs.into_iter(),
                self.orchestrator.provider(),
            )
            .await?;

        // Remove the fee from the asset diff payer as to not confuse the user.
        let payer = if intent.payer.is_zero() { intent.eoa } else { intent.payer };
        if payer == intent.eoa {
            asset_diffs.remove_payer_fee(payer, intent.paymentToken.into(), U256::from(1));
        }

        Ok((asset_diffs, result.gas))
    }

    /// Call `Orchestrator.execute` with the provided [`Intent`].
    pub async fn execute(&self, intent: &Intent) -> Result<(), RelayError> {
        let ret = self
            .orchestrator
            .execute(intent.abi_encode().into())
            .call()
            .overrides(self.overrides.clone())
            .await
            .map_err(TransportErrorKind::custom)?;

        if ret != ORCHESTRATOR_NO_ERROR {
            Err(IntentError::intent_revert(ret.into()).into())
        } else {
            Ok(())
        }
    }

    /// Get the [`Eip712Domain`] for this orchestrator.
    ///
    /// If `multichain` is `true`, then the chain ID is omitted from the domain.
    pub async fn eip712_domain(&self, multichain: bool) -> TransportResult<Eip712Domain> {
        let domain = self
            .orchestrator
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

    /// Whether the orchestrator has been paused.
    pub async fn is_paused(&self) -> TransportResult<bool> {
        Ok(self
            .orchestrator
            .pauseFlag()
            .call()
            .overrides(self.overrides.clone())
            .await
            .map_err(TransportErrorKind::custom)?
            == U256::ONE)
    }
}

impl IntentExecuted {
    /// Attempts to decode the [`IntentExecuted`] event from the receipt.
    pub fn try_from_receipt(receipt: &TransactionReceipt) -> Option<Self> {
        receipt.decoded_log::<Self>().map(|e| e.data)
    }

    /// Whether the intent execution failed.
    pub fn has_error(&self) -> bool {
        self.err != ORCHESTRATOR_NO_ERROR
    }
}
