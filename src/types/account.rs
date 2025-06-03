use super::{
    Key, KeyHash, OrchestratorContract::accountImplementationOfCall, Signature, rpc::Permission,
};
use crate::{
    error::{AuthError, RelayError},
    types::IDelegation,
};
use IthacaAccount::{
    IthacaAccountInstance, spendAndExecuteInfosReturn, unwrapAndValidateSignatureReturn,
};
use alloy::{
    eips::eip7702::constants::{EIP7702_CLEARED_DELEGATION, EIP7702_DELEGATION_DESIGNATOR},
    primitives::{Address, B256, Bytes, FixedBytes, U256, aliases::U192, map::HashMap},
    providers::Provider,
    rpc::types::{
        TransactionRequest,
        state::{AccountOverride, StateOverride, StateOverridesBuilder},
    },
    sol,
    sol_types::{SolCall, SolValue},
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

        /// Returns the EIP712 domain of the delegation.
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

    /// Get the version of the account.
    pub async fn version(&self) -> TransportResult<String> {
        Ok(self
            .delegation
            .eip712Domain()
            .call()
            .overrides(self.overrides.clone())
            .await
            .map_err(TransportErrorKind::custom)?
            .version)
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

    /// Validates the given signature, returns `Some(key_hash)` if the signature is valid.
    pub async fn validate_signature(
        &self,
        digest: B256,
        signature: Signature,
    ) -> TransportResult<Option<KeyHash>> {
        let unwrapAndValidateSignatureReturn { isValid, keyHash } = self
            .delegation
            .unwrapAndValidateSignature(digest, signature.abi_encode_packed().into())
            .call()
            .overrides(self.overrides.clone())
            .await
            .map_err(TransportErrorKind::custom)?;

        Ok(isValid.then_some(keyHash))
    }

    /// Get the next nonce for the given EOA.
    ///
    /// # Note
    ///
    /// This gets the next nonce for sequence key `0`.
    pub async fn get_nonce(&self) -> TransportResult<U256> {
        self.delegation
            .getNonce(DEFAULT_SEQUENCE_KEY)
            .call()
            .overrides(self.overrides.clone())
            .await
            .map_err(TransportErrorKind::custom)
    }
}
