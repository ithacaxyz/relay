use super::{
    Key, KeyHash, MULTICHAIN_NONCE_PREFIX_U192, OrchestratorContract::accountImplementationOfCall,
    rpc::Permission, storage::CreatableAccount,
};
use crate::{
    error::{AuthError, RelayError},
    storage::StorageApi,
    types::IDelegation,
};
use IthacaAccount::{
    IthacaAccountInstance, spendAndExecuteInfosReturn, unwrapAndValidateSignatureReturn,
};
use alloy::{
    dyn_abi::Eip712Domain,
    eips::eip7702::constants::{EIP7702_CLEARED_DELEGATION, EIP7702_DELEGATION_DESIGNATOR},
    primitives::{
        Address, B256, Bytes, FixedBytes, U256,
        aliases::{B192, U192},
        map::HashMap,
    },
    providers::{DynProvider, Provider},
    rpc::types::{
        TransactionRequest,
        state::{AccountOverride, StateOverride, StateOverridesBuilder},
    },
    sol,
    sol_types::{SolCall, SolStruct},
    transports::{TransportErrorKind, TransportResult},
    uint,
};
use serde::{Deserialize, Serialize};
use tracing::debug;

/// Default sequence key used on prepareCalls.
pub const DEFAULT_SEQUENCE_KEY: U192 = uint!(0_U192);

sol! {
    #[sol(rpc)]
    #[derive(Debug)]
    contract DelegationProxy {
        /// The default implementation address.
        address public implementation;
    }
}

sol! {
    #[sol(rpc)]
    #[derive(Debug)]
    contract IthacaAccount {
        /// A spend period.
        #[derive(Eq, PartialEq, Serialize, Deserialize)]
        #[serde(rename_all = "lowercase")]
        enum SpendPeriod {
            /// Per minute.
            Minute,
            /// Per hour.
            Hour,
            /// Per day.
            Day,
            /// Per week.
            Week,
            /// Per month.
            Month,
            /// Per year.
            Year
        }


        /// Information about a spend.
        /// All timestamp related values are Unix timestamps in seconds.
        #[derive(Eq, PartialEq)]
        struct SpendInfo {
            /// Address of the token. `address(0)` denotes native token.
            address token;
            /// The type of period.
            SpendPeriod period;
            /// The maximum spend limit for the period.
            uint256 limit;
            /// The amount spent in the last updated period.
            uint256 spent;
            /// The start of the last updated period.
            uint256 lastUpdated;
            /// The amount spent in the current period.
            uint256 currentSpent;
            /// The start of the current period.
            uint256 current;
        }

        /// The key does not exist.
        error KeyDoesNotExist();

        /// The `opData` is too short.
        error OpDataTooShort();

        /// @dev The `keyType` cannot be super admin.
        error KeyTypeCannotBeSuperAdmin();

        /// Cannot set or get the permissions if the `keyHash` is `bytes32(0)`.
        error KeyHashIsZero();

        /// Only the EOA itself and super admin keys can self execute.
        error CannotSelfExecute();

        /// Unauthorized to perform the action.
        error Unauthorized();

        /// Exceeded the spend limit.
        error ExceededSpendLimit(address token);

        /// @dev In order to spend a token, it must have spend permissions set.
        error NoSpendPermissions();

        /// Super admin keys can execute everything.
        error SuperAdminCanExecuteEverything();

        /// @dev Super admin keys can spend anything.
        error SuperAdminCanSpendAnything();

        /// The execution mode is not supported.
        error UnsupportedExecutionMode();

        /// Cannot decode `executionData` as a batch of batches `abi.encode(bytes[])`.
        error BatchOfBatchesDecodingError();

        /// The function selector is not recognized.
        error FnSelectorNotRecognized();

        /// Return current nonce with sequence key.
        function getNonce(uint192 seqKey) public view virtual returns (uint256);

        /// Set a limited amount of `token` that `keyHash` can spend per `period`.
        function setSpendLimit(bytes32 keyHash, address token, SpendPeriod period, uint256 limit)
            public
            virtual
            onlyThis
            checkKeyHashIsNonZero(keyHash);

        /// Removes the daily spend limit of `token` for `keyHash` for `period`.
        function removeSpendLimit(bytes32 keyHash, address token, SpendPeriod period)
            public
            virtual
            onlyThis
            checkKeyHashIsNonZero(keyHash);

        /// Sets the ability of a key hash to execute a call with a function selector.
        function setCanExecute(bytes32 keyHash, address target, bytes4 fnSel, bool can);

        /// Returns spend and execute infos for each provided key hash in the same order.
        ///
        /// canExecute elements are packed as (`target`, `fnSel`):
        /// - `target` is in the upper 20 bytes.
        /// - `fnSel` is in the lower 4 bytes.
        function spendAndExecuteInfos(bytes32[] calldata keyHashes) returns (SpendInfo[][] memory keys_spends, bytes32[][] memory keys_executes);

        /// The orchestrator address.
        address public ORCHESTRATOR;

        /// Returns whether the given signature is valid and a keyHash that signed the digest.
        function unwrapAndValidateSignature(bytes32 digest, bytes calldata signature)
            public
            view
            virtual
            returns (bool isValid, bytes32 keyHash);

        /// The implementation address.
        address public implementation;

        /// Upgrades the implementation.
        function upgradeProxyAccount(address newImplementation);

        /// ERC1271 replay-safe signature struct
        struct ERC1271Sign {
            bytes32 digest;
        }

        /// Returns the EIP712 domain separator information
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

impl spendAndExecuteInfosReturn {
    /// Converts [`spendAndExecuteInfosReturn`] into a list of [`Permission`] per key.
    ///
    /// On each key, the spend permissions come before the call ones.
    pub fn into_permissions(self) -> Vec<Vec<Permission>> {
        self.keys_spends
            .into_iter()
            .zip(self.keys_executes)
            .map(|(spends, executes)| {
                spends
                    .into_iter()
                    .map(|spend| Permission::Spend(spend.into()))
                    .chain(executes.into_iter().map(|data| {
                        Permission::Call(CallPermission {
                            to: Address::from_slice(&data[..20]),
                            selector: FixedBytes::from_slice(&data[28..]),
                        })
                    }))
                    .collect()
            })
            .collect()
    }
}

/// Represents a granted allowance to execute a specific function on a target contract.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CallPermission {
    /// The 4-byte selector of the allowed function.
    #[serde(deserialize_with = "crate::serde::fn_selector::deserialize")]
    pub selector: FixedBytes<4>,
    /// The target contract's address.
    pub to: Address,
}

/// A Ithaca account.
#[derive(Debug, Clone)]
pub struct Account<P: Provider> {
    delegation: IthacaAccountInstance<P>,
    overrides: StateOverride,
}

impl<P: Provider> Account<P> {
    /// Create a new instance of [`Account`].
    pub fn new(address: Address, provider: P) -> Self {
        Self {
            delegation: IthacaAccountInstance::new(address, provider),
            overrides: StateOverride::default(),
        }
    }

    /// Returns the address of the account.
    pub fn address(&self) -> Address {
        *self.delegation.address()
    }

    /// Sets a 7702 delegation override on this account.
    pub fn with_delegation_override(mut self, address: &Address) -> Self {
        self.overrides = StateOverridesBuilder::with_capacity(1)
            .append(
                *self.delegation.address(),
                AccountOverride::default().with_code(Bytes::from(
                    [&EIP7702_DELEGATION_DESIGNATOR, address.as_slice()].concat(),
                )),
            )
            .build();
        self
    }

    /// Sets a 7702 delegation override on this account.Add commentMore actions
    pub fn with_delegation_override_opt(self, address: Option<&Address>) -> Self {
        if let Some(address) = address { self.with_delegation_override(address) } else { self }
    }

    /// Sets overrides for all calls on this account.
    pub fn with_overrides(mut self, overrides: StateOverride) -> Self {
        self.overrides = overrides;
        self
    }

    /// Returns this account delegation implementation if it exists.
    ///
    /// The `accountImplementationOf` call to the orchestrator also verifies that the delegation
    /// proxy is valid. If it's not, this will return an error.
    pub async fn delegation_implementation(&self) -> Result<Option<Address>, RelayError> {
        // Only query eth_getCode, if there is no 7702 code override present for the account
        if !self.overrides.iter().any(|(address, over)| {
            *address == self.address()
                && over
                    .code
                    .as_ref()
                    .is_some_and(|code| code.starts_with(&EIP7702_DELEGATION_DESIGNATOR))
        }) && !self.is_delegated().await?
        {
            return Ok(None);
        }

        let delegation = self
            .delegation
            .provider()
            .call(
                TransactionRequest::default()
                    .to(self.get_orchestrator().await?)
                    .input(accountImplementationOfCall { eoa: self.address() }.abi_encode().into()),
            )
            .overrides(self.overrides.clone())
            .await
            .and_then(|ret| {
                accountImplementationOfCall::abi_decode_returns(&ret)
                    .map_err(TransportErrorKind::custom)
            })
            .map_err(RelayError::from)?;

        // A zero address means an invalid delegation proxy.
        if delegation.is_zero() {
            return Err(RelayError::Auth(AuthError::InvalidDelegationProxy(delegation).boxed()));
        }

        Ok(Some(delegation))
    }

    /// Whether this account is delegated.
    pub async fn is_delegated(&self) -> Result<bool, RelayError> {
        let code = self
            .delegation
            .provider()
            .get_code_at(*self.delegation.address())
            .await
            .map_err(RelayError::from)?;

        Ok(code.get(..3) == Some(&EIP7702_DELEGATION_DESIGNATOR[..])
            && code[..] != EIP7702_CLEARED_DELEGATION)
    }

    /// Gets the delegation status of the account.
    ///
    /// Checks both on-chain delegation and stored authorizations.
    pub async fn delegation_status<S: StorageApi>(
        &self,
        storage: &S,
    ) -> Result<DelegationStatus, RelayError>
    where
        P: Clone,
    {
        // Check if account is delegated on-chain
        if let Some(implementation) = self.delegation_implementation().await? {
            return Ok(DelegationStatus::Delegated { implementation });
        }

        // Check if there's a stored authorization
        if let Some(stored) = storage.read_account(&self.address()).await? {
            // Get the implementation address the delegation proxy points to
            let account_with_delegation =
                self.clone().with_delegation_override(stored.signed_authorization.address());

            if let Some(implementation) =
                account_with_delegation.delegation_implementation().await?
            {
                return Ok(DelegationStatus::Stored { account: Box::new(stored), implementation });
            } else {
                return Err(RelayError::Auth(
                    AuthError::InvalidDelegationProxy(*stored.signed_authorization.address())
                        .boxed(),
                ));
            }
        }

        Ok(DelegationStatus::None { eoa: self.address() })
    }

    /// Returns a list of all non expired keys as (KeyHash, Key) tuples.
    pub async fn keys(&self) -> TransportResult<Vec<(B256, Key)>> {
        debug!(eoa = %self.delegation.address(), "Fetching keys");

        let keys = self
            .delegation
            .provider()
            .call(
                TransactionRequest::default()
                    .to(*self.delegation.address())
                    .input(IDelegation::getKeysCall::SELECTOR.to_vec().into()),
            )
            .overrides(self.overrides.clone())
            .await
            .and_then(|r| {
                IDelegation::getKeysCall::abi_decode_returns(&r).map_err(TransportErrorKind::custom)
            })?;

        debug!(
            eoa = %self.delegation.address(),
            keys = ?keys.keys,
            "Fetched keys"
        );

        Ok(keys.into_tuples().collect())
    }

    /// Returns a list of all permissions for the given key set.
    pub async fn permissions(
        &self,
        key_hashes: impl Iterator<Item = B256> + Clone,
    ) -> TransportResult<HashMap<B256, Vec<Permission>>> {
        debug!(eoa = %self.delegation.address(), "Fetching permissions");

        let permissions = self
            .delegation
            .spendAndExecuteInfos(key_hashes.clone().collect())
            .call()
            .overrides(self.overrides.clone())
            .await
            .map_err(TransportErrorKind::custom)?
            .into_permissions();

        debug!(
            eoa = %self.delegation.address(),
            permissions = ?permissions,
            "Fetched keys permissions"
        );

        Ok(key_hashes.zip(permissions).collect())
    }

    /// Fetch the orchestrator address from the delegation contract.
    pub async fn get_orchestrator(&self) -> TransportResult<Address> {
        self.delegation
            .ORCHESTRATOR()
            .call()
            .overrides(self.overrides.clone())
            .await
            .map_err(TransportErrorKind::custom)
    }

    /// Validates the given signature with ERC1271 replay-safe wrapping.
    ///
    /// Returns `Some(key_hash)` if the signature is valid.
    pub async fn validate_signature(
        &self,
        digest: B256,
        signature: Bytes,
    ) -> Result<Option<KeyHash>, RelayError> {
        let unwrapAndValidateSignatureReturn { isValid, keyHash } = self
            .delegation
            .unwrapAndValidateSignature(digest, signature)
            .call()
            .overrides(self.overrides.clone())
            .await?;

        Ok(isValid.then_some(keyHash))
    }

    /// Wraps a digest for ERC1271 signature validation.
    ///
    /// This implements the same logic as IthacaAccount.sol's isValidSignature function.
    pub fn digest_erc1271(&self, digest: B256) -> B256 {
        let domain = Eip712Domain::new(None, None, None, Some(*self.delegation.address()), None);

        IthacaAccount::ERC1271Sign { digest }.eip712_signing_hash(&domain)
    }

    /// Get the next nonce for the given EOA.
    ///
    /// # Note
    ///
    /// This gets the next nonce for sequence key `0`.
    pub async fn get_nonce(&self) -> TransportResult<U256> {
        self.get_nonce_for_sequence(DEFAULT_SEQUENCE_KEY).await
    }

    /// Get the next nonce for the given sequence key.
    pub async fn get_nonce_for_sequence(&self, sequence_key: U192) -> TransportResult<U256> {
        self.delegation
            .getNonce(sequence_key)
            .call()
            .overrides(self.overrides.clone())
            .await
            .map_err(TransportErrorKind::custom)
    }
}

impl Account<DynProvider> {
    /// Generates a random nonce with a random sequence key.
    ///
    /// This is useful for accounts that may be sponsoring many concurrent intents (e.g.,
    /// fee_payer), where sequential nonces could cause bottlenecks. The random sequence key
    /// ensures that each intent gets a unique nonce without coordination.
    ///
    /// The function ensures the generated sequence key doesn't conflict with the multichain nonce
    /// prefix.
    pub fn random_nonce() -> U256 {
        loop {
            let sequence_key = U192::from_be_bytes(B192::random().into());
            if sequence_key >> 176 != MULTICHAIN_NONCE_PREFIX_U192 {
                break U256::from(sequence_key) << 64;
            }
        }
    }
}

/// Represents the delegation status of an account.
#[derive(Debug, Clone)]
pub enum DelegationStatus {
    /// Account is not delegated yet but has a stored authorization with implementation.
    Stored {
        /// The stored account data.
        account: Box<CreatableAccount>,
        /// The implementation address the delegation proxy points to.
        implementation: Address,
    },
    /// Account is delegated with the given implementation address.
    Delegated {
        /// The current delegation implementation address.
        implementation: Address,
    },
    /// Account has no delegation.
    None {
        /// The EOA address that has no delegation.
        eoa: Address,
    },
}

impl DelegationStatus {
    /// Returns the implementation address if there is one, or error if None.
    pub fn try_implementation(&self) -> Result<Address, RelayError> {
        match self {
            DelegationStatus::Stored { implementation, .. } => Ok(*implementation),
            DelegationStatus::Delegated { implementation } => Ok(*implementation),
            DelegationStatus::None { eoa } => {
                Err(RelayError::Auth(AuthError::EoaNotDelegated(*eoa).boxed()))
            }
        }
    }

    /// Returns the stored account if this is a Stored status (not delegated on the target chain)
    pub fn stored_account(&self) -> Option<&CreatableAccount> {
        match self {
            DelegationStatus::Stored { account, .. } => Some(account.as_ref()),
            _ => None,
        }
    }

    /// Returns true if the account is delegated on-chain.
    pub fn is_delegated(&self) -> bool {
        matches!(self, DelegationStatus::Delegated { .. })
    }

    /// Returns true if the account has stored authorization but is not yet delegated on-chain.
    pub fn is_stored(&self) -> bool {
        matches!(self, DelegationStatus::Stored { .. })
    }

    /// Returns true if the account is not delegated on-chain or in storage
    pub fn is_unknown(&self) -> bool {
        matches!(self, DelegationStatus::None { .. })
    }
}
