use OrchestratorContract::OrchestratorContractInstance;
use alloy::{
    dyn_abi::Eip712Domain,
    primitives::{Address, ChainId, FixedBytes, U256, fixed_bytes},
    providers::Provider,
    rpc::types::{TransactionReceipt, state::StateOverride},
    sol,
    sol_types::SolValue,
    transports::{TransportErrorKind, TransportResult},
};

use super::{GasResults, simulator::SimulatorContract};
use crate::{
    asset::AssetInfoServiceHandle,
    cache::RpcCache,
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
    /// Optional cache for EIP712Domains
    cache: Option<RpcCache>,
}

impl<P: Provider> Orchestrator<P> {
    /// Create a new instance of [`Entry`].
    pub fn new(address: Address, provider: P) -> Self {
        Self {
            orchestrator: OrchestratorContractInstance::new(address, provider),
            overrides: StateOverride::default(),
            cache: None,
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

    /// Add cache support to orchestrator for EIP712Domain caching.
    pub fn with_cache(mut self, cache: RpcCache) -> Self {
        self.cache = Some(cache);
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
    /// Domains are cached per chain to reduce redundant RPC calls.
    pub async fn eip712_domain(&self, multichain: bool) -> TransportResult<Eip712Domain> {
        // Get chain id from provider
        let provider_chain_id = self.orchestrator.provider().get_chain_id().await?;
        let chain_id = ChainId::from(provider_chain_id);

        // Try cache first and return early if present
        if let Some(domain) = self
            .cache
            .as_ref()
            .and_then(|cache| cache.get_eip712_domain(self.address(), chain_id, multichain))
        {
            return Ok(domain);
        }

        // Otherwise, fetch from RPC and create appropriate domain variant
        let fetched = self.fetch_eip712_domain_from_rpc().await?;

        let result = if multichain {
            // Create multichain variant (no chain ID)
            Eip712Domain::new(
                fetched.name,
                fetched.version,
                None, // Omit chain ID for multichain
                fetched.verifying_contract,
                fetched.salt,
            )
        } else {
            // Use single-chain variant (with chain ID)
            fetched
        };

        // Cache the appropriate variant
        if let Some(cache) = &self.cache {
            cache.set_eip712_domain(*self.address(), chain_id, result.clone(), multichain);
        }

        Ok(result)
    }

    /// Fetch the EIP712 domain from the RPC and convert into `Eip712Domain`.
    async fn fetch_eip712_domain_from_rpc(&self) -> TransportResult<Eip712Domain> {
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
            Some(domain.chainId),
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

#[cfg(test)]
mod orchestrator_cache_tests {
    use crate::cache::RpcCache;
    use alloy::{
        dyn_abi::Eip712Domain,
        primitives::{ChainId, U256, address},
    };

    #[test]
    fn test_multichain_domain_caching_separation() {
        let cache = RpcCache::new();
        let orchestrator_addr = address!("1234567890123456789012345678901234567890");
        let chain_id = ChainId::from(1u64);

        // Create single-chain domain (with chain ID)
        let single_chain_domain = Eip712Domain::new(
            Some("TestOrchestrator".into()),
            Some("1.0.0".into()),
            Some(U256::from(chain_id)),
            Some(orchestrator_addr),
            None,
        );

        // Create multichain domain (without chain ID)
        let multichain_domain = Eip712Domain::new(
            Some("TestOrchestrator".into()),
            Some("1.0.0".into()),
            None, // No chain ID for multichain
            Some(orchestrator_addr),
            None,
        );

        // Cache single-chain domain
        cache.set_eip712_domain(orchestrator_addr, chain_id, single_chain_domain.clone(), false);

        // Cache multichain domain
        cache.set_eip712_domain(orchestrator_addr, chain_id, multichain_domain.clone(), true);

        // Verify single-chain domain retrieval
        let retrieved_single = cache.get_eip712_domain(&orchestrator_addr, chain_id, false);
        assert!(retrieved_single.is_some());
        assert_eq!(retrieved_single.unwrap().chain_id, Some(U256::from(chain_id)));

        // Verify multichain domain retrieval
        let retrieved_multi = cache.get_eip712_domain(&orchestrator_addr, chain_id, true);
        assert!(retrieved_multi.is_some());
        assert_eq!(retrieved_multi.unwrap().chain_id, None);

        // Verify they are different entries
        assert_ne!(
            cache.get_eip712_domain(&orchestrator_addr, chain_id, false),
            cache.get_eip712_domain(&orchestrator_addr, chain_id, true)
        );
    }

    #[test]
    fn test_cache_miss_scenarios() {
        let cache = RpcCache::new();
        let orchestrator_addr = address!("1234567890123456789012345678901234567890");
        let chain_id_1 = ChainId::from(1u64);
        let chain_id_2 = ChainId::from(2u64);

        // Create and cache a domain for chain 1, single-chain
        let domain = Eip712Domain::new(
            Some("TestOrchestrator".into()),
            Some("1.0.0".into()),
            Some(U256::from(chain_id_1)),
            Some(orchestrator_addr),
            None,
        );
        cache.set_eip712_domain(orchestrator_addr, chain_id_1, domain.clone(), false);

        // Should get cache hit for correct parameters
        assert!(cache.get_eip712_domain(&orchestrator_addr, chain_id_1, false).is_some());

        // Should get cache miss for different chain
        assert!(cache.get_eip712_domain(&orchestrator_addr, chain_id_2, false).is_none());

        // Should get cache miss for same chain but multichain variant
        assert!(cache.get_eip712_domain(&orchestrator_addr, chain_id_1, true).is_none());

        // Should get cache miss for different orchestrator
        let other_orchestrator = address!("abcdefabcdefabcdefabcdefabcdefabcdefabcd");
        assert!(cache.get_eip712_domain(&other_orchestrator, chain_id_1, false).is_none());
    }

    #[test]
    fn test_cache_key_uniqueness() {
        let cache = RpcCache::new();
        let orchestrator_1 = address!("1111111111111111111111111111111111111111");
        let orchestrator_2 = address!("2222222222222222222222222222222222222222");
        let chain_id_1 = ChainId::from(1u64);
        let chain_id_2 = ChainId::from(2u64);

        // Create domains with different combinations
        let domain_1_1_false = Eip712Domain::new(
            Some("Domain11F".into()),
            Some("1.0.0".into()),
            Some(U256::from(chain_id_1)),
            Some(orchestrator_1),
            None,
        );
        let domain_1_1_true = Eip712Domain::new(
            Some("Domain11T".into()),
            Some("1.0.0".into()),
            None,
            Some(orchestrator_1),
            None,
        );
        let domain_1_2_false = Eip712Domain::new(
            Some("Domain12F".into()),
            Some("1.0.0".into()),
            Some(U256::from(chain_id_2)),
            Some(orchestrator_1),
            None,
        );
        let domain_2_1_false = Eip712Domain::new(
            Some("Domain21F".into()),
            Some("1.0.0".into()),
            Some(U256::from(chain_id_1)),
            Some(orchestrator_2),
            None,
        );

        // Cache all combinations
        cache.set_eip712_domain(orchestrator_1, chain_id_1, domain_1_1_false.clone(), false);
        cache.set_eip712_domain(orchestrator_1, chain_id_1, domain_1_1_true.clone(), true);
        cache.set_eip712_domain(orchestrator_1, chain_id_2, domain_1_2_false.clone(), false);
        cache.set_eip712_domain(orchestrator_2, chain_id_1, domain_2_1_false.clone(), false);

        // Verify each combination retrieves the correct domain
        assert_eq!(
            cache.get_eip712_domain(&orchestrator_1, chain_id_1, false).unwrap().name,
            Some("Domain11F".into())
        );
        assert_eq!(
            cache.get_eip712_domain(&orchestrator_1, chain_id_1, true).unwrap().name,
            Some("Domain11T".into())
        );
        assert_eq!(
            cache.get_eip712_domain(&orchestrator_1, chain_id_2, false).unwrap().name,
            Some("Domain12F".into())
        );
        assert_eq!(
            cache.get_eip712_domain(&orchestrator_2, chain_id_1, false).unwrap().name,
            Some("Domain21F".into())
        );

        // Verify cache misses for non-existent combinations
        assert!(cache.get_eip712_domain(&orchestrator_1, chain_id_2, true).is_none());
        assert!(cache.get_eip712_domain(&orchestrator_2, chain_id_1, true).is_none());
        assert!(cache.get_eip712_domain(&orchestrator_2, chain_id_2, false).is_none());
        assert!(cache.get_eip712_domain(&orchestrator_2, chain_id_2, true).is_none());
    }
}
