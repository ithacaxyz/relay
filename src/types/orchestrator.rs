use OrchestratorContract::OrchestratorContractInstance;
use alloy::{
    dyn_abi::Eip712Domain,
    primitives::{Address, FixedBytes, U256, fixed_bytes},
    providers::Provider,
    rpc::types::{TransactionReceipt, state::StateOverride},
    sol,
    transports::TransportErrorKind,
};
use futures::TryFutureExt;
use serde::{Deserialize, Serialize};
use tokio::try_join;
use tracing::debug;

use super::{GasResults, contracts::VersionedContract, simulator::SimulatorContract};
use crate::{
    asset::AssetInfoServiceHandle,
    config::SimMode,
    error::{IntentError, RelayError},
    types::{
        Asset, AssetDeficit, AssetDeficits, AssetDiffs,
        IERC20::{self, balanceOfCall},
        Intent,
        OrchestratorContract::IntentExecuted,
        SimulationExecutionResult,
    },
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

        /// @dev DEPRECATION WARNING: This function will be deprecated in the future.
        /// Allows pre calls to be executed individually, for counterfactual signatures.
        function executePreCalls(address parentEOA, SignedCall[] calldata preCalls) public virtual;

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

        /// Can be used to pause/unpause the contract, in case of emergencies.
        function pause(bool isPause) public;

        /// Returns the pause authority and the last pause timestamp.
        function getPauseConfig() public view virtual returns (address, uint40);
    }

    /// A struct to hold the fields for a PreCall.
    /// Like a Intent with a subset of fields.
    #[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct SignedCall {
        /// The user's address.
        ///
        /// This can be set to `address(0)`, which allows it to be
        /// coalesced to the parent Intent's EOA.
        address eoa;
        /// An encoded array of calls, using ERC7579 batch execution encoding.
        ///
        /// `abi.encode(calls)`, where `calls` is of type `Call[]`.
        /// This allows for more efficient safe forwarding to the EOA.
        bytes executionData;
        /// Per delegated EOA. Same logic as the `nonce` in Intent.
        uint256 nonce;
        /// The wrapped signature.
        ///
        /// `abi.encodePacked(innerSignature, keyHash, prehash)`.
        bytes signature;
    }
}

/// The orchestrator.
#[derive(Debug)]
pub struct Orchestrator<P: Provider> {
    orchestrator: OrchestratorContractInstance<P>,
    overrides: StateOverride,
    versioned_contract: VersionedContract,
}

impl<P: Provider> Orchestrator<P> {
    /// Create a new instance of [`Orchestrator`].
    pub fn new(versioned_contract: VersionedContract, provider: P) -> Self {
        let address = versioned_contract.address;
        Self {
            orchestrator: OrchestratorContractInstance::new(address, provider),
            overrides: StateOverride::default(),
            versioned_contract,
        }
    }

    /// Get the address of the orchestrator.
    pub fn address(&self) -> &Address {
        self.orchestrator.address()
    }

    /// Get the version of the orchestrator.
    pub fn version(&self) -> Option<&semver::Version> {
        self.versioned_contract.version.as_ref()
    }

    /// Get the versioned contract.
    pub fn versioned_contract(&self) -> &VersionedContract {
        &self.versioned_contract
    }

    /// Sets overrides for all calls on this orchestrator.
    pub fn with_overrides(mut self, overrides: StateOverride) -> Self {
        self.overrides = overrides;
        self
    }

    /// Call `Simulator.simulateV1Logs` with the provided [`Intent`].
    ///
    /// `simulator` contract address should have its balance set to `uint256.max`.
    ///
    /// This respects the given [`SimMode`] when performing the simulation.
    #[expect(clippy::too_many_arguments)]
    pub async fn simulate_execute(
        &self,
        mock_from: Address,
        simulator: Address,
        intent: &Intent,
        asset_info_handle: AssetInfoServiceHandle,
        gas_validation_offset: U256,
        sim_mode: SimMode,
        calculate_asset_deficits: bool,
    ) -> Result<(AssetDiffs, AssetDeficits, GasResults), RelayError> {
        let result = SimulatorContract::new(
            simulator,
            self.orchestrator.provider(),
            self.overrides.clone(),
            sim_mode,
            calculate_asset_deficits,
        )
        .simulate(*self.address(), mock_from, intent, gas_validation_offset, self.version())
        .await?;

        let chain_id = self.orchestrator.provider().get_chain_id().await?;

        debug!(chain_id, block_number = %result.block_number, account = %intent.eoa(), nonce = %intent.nonce(), "simulation executed");

        // calculate asset diffs using the transaction request from simulation
        let (asset_diffs, asset_deficits) = try_join!(
            self.build_asset_diffs(&result, intent, &asset_info_handle),
            self.build_asset_deficits(&result, intent, &asset_info_handle),
        )?;

        Ok((asset_diffs, asset_deficits, result.gas))
    }

    /// Builds [`AssetDeficits`] from a [`SimulationExecutionResult`].
    async fn build_asset_deficits(
        &self,
        result: &SimulationExecutionResult,
        intent: &Intent,
        asset_info_handle: &AssetInfoServiceHandle,
    ) -> Result<AssetDeficits, RelayError> {
        if result.asset_deficits.is_empty() {
            return Ok(AssetDeficits::default());
        }

        let mut balances = self
            .orchestrator
            .provider()
            .multicall()
            .block(result.block_number.into())
            .dynamic::<balanceOfCall>();

        for asset in result.asset_deficits.keys() {
            balances = balances.add_dynamic(
                IERC20::new(*asset, self.orchestrator.provider()).balanceOf(*intent.eoa()),
            );
        }

        let (mut metadata, balances) = try_join!(
            asset_info_handle.get_asset_info_list(
                self.orchestrator.provider(),
                result.asset_deficits.keys().map(|address| Asset::Token(*address)).collect(),
            ),
            balances.aggregate().map_err(RelayError::from)
        )?;

        let mut deficits = Vec::with_capacity(result.asset_deficits.len());
        for ((&asset, required), balance) in result.asset_deficits.iter().zip(balances) {
            let Some(info) = metadata.remove(&Asset::Token(asset)) else {
                continue;
            };

            let mut required = *required;

            // Remove the fee from the required amount as to not confuse the user.
            let payer = if intent.payer().is_zero() { *intent.eoa() } else { intent.payer() };
            if payer == *intent.eoa() && asset == intent.payment_token() {
                required -= U256::from(1);
            }

            deficits.push(AssetDeficit {
                address: Some(asset),
                metadata: info.metadata,
                required,
                deficit: required.saturating_sub(balance),
                fiat: None,
            });
        }

        Ok(AssetDeficits(deficits))
    }

    /// Builds [`AssetDiffs`] from a [`SimulationExecutionResult`].
    async fn build_asset_diffs(
        &self,
        result: &SimulationExecutionResult,
        intent: &Intent,
        asset_info_handle: &AssetInfoServiceHandle,
    ) -> Result<AssetDiffs, RelayError> {
        let mut asset_diffs = asset_info_handle
            .calculate_asset_diff(
                &result.tx_request,
                self.overrides.clone(),
                &result.logs,
                self.orchestrator.provider(),
            )
            .await?;

        // Remove the fee from the asset diff payer as to not confuse the user.
        let payer = if intent.payer().is_zero() { *intent.eoa() } else { intent.payer() };
        if payer == *intent.eoa() {
            asset_diffs.remove_payer_fee(payer, intent.payment_token().into(), U256::from(1));
        }

        Ok(asset_diffs)
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
    pub fn eip712_domain(&self, multichain: bool) -> Eip712Domain {
        self.versioned_contract.eip712_domain(multichain)
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
