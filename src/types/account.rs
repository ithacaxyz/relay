use super::{
    Call,
    IDelegation::authorizeCall,
    Key, KeyHash, Signature,
    rpc::{AuthorizeKey, AuthorizeKeyResponse, Permission},
};
use crate::{error::RelayError, types::IDelegation};
use Delegation::{
    DelegationInstance, spendAndExecuteInfosReturn, unwrapAndValidateSignatureReturn,
};
use alloy::{
    eips::eip7702::{
        SignedAuthorization,
        constants::{EIP7702_CLEARED_DELEGATION, EIP7702_DELEGATION_DESIGNATOR},
    },
    primitives::{Address, B256, Bytes, FixedBytes, Keccak256, U256, keccak256, map::HashMap},
    providers::{MulticallError, Provider},
    rpc::types::{Authorization, TransactionRequest, state::StateOverride},
    sol,
    sol_types::{SolCall, SolStruct, SolValue},
    transports::{TransportErrorKind, TransportResult},
};
use serde::{Deserialize, Serialize};
use tracing::debug;

sol! {
    #[sol(rpc)]
    #[derive(Debug)]
    contract Delegation {
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

        /// The PREP `initData` is invalid.
        error InvalidPREP();

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

        /// The entrypoint address.
        address public ENTRY_POINT;

        /// Returns whether the given signature is valid and a keyHash that signed the digest.
        function unwrapAndValidateSignature(bytes32 digest, bytes calldata signature)
            public
            view
            virtual
            returns (bool isValid, bytes32 keyHash);

        /// Initializes PREP account with given `initData`.
        function initializePREP(bytes calldata initData) public virtual returns (bool);

        /// The implementation address.
        address public implementation;
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

/// A Porto account.
#[derive(Debug)]
pub struct Account<P: Provider> {
    delegation: DelegationInstance<P>,
    overrides: StateOverride,
}

impl<P: Provider> Account<P> {
    /// Create a new instance of [`Account`].
    pub fn new(address: Address, provider: P) -> Self {
        Self {
            delegation: DelegationInstance::new(address, provider),
            overrides: StateOverride::default(),
        }
    }

    /// Returns the address of the account.
    pub fn address(&self) -> Address {
        *self.delegation.address()
    }

    /// Sets overrides for all calls on this account.
    pub fn with_overrides(mut self, overrides: StateOverride) -> Self {
        self.overrides = overrides;
        self
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

    /// Fetch the entrypoint address from the delegation contract.
    pub async fn get_entrypoint(&self) -> TransportResult<Address> {
        self.delegation
            .ENTRY_POINT()
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

    /// A helper to combine `initializePREP` and `validateSignature` calls into a single multicall.
    pub async fn initialize_and_validate_signature(
        &self,
        init_data: Bytes,
        digest: B256,
        signature: Signature,
    ) -> Result<Option<B256>, MulticallError> {
        let (_, unwrapAndValidateSignatureReturn { isValid, keyHash }) = self
            .delegation
            .provider()
            .multicall()
            .add(self.delegation.initializePREP(init_data))
            .add(
                self.delegation
                    .unwrapAndValidateSignature(digest, signature.abi_encode_packed().into()),
            )
            .overrides(self.overrides.clone())
            .aggregate()
            .await?;

        Ok(isValid.then_some(keyHash))
    }
}

/// PREP account based on <https://blog.biconomy.io/prep-deep-dive/>.
///
/// Read [`PREPAccount::initialize`] for more information on how it is generated.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PREPAccount {
    /// EOA generated address.
    pub address: Address,
    /// Signed 7702 authorization.
    pub signed_authorization: SignedAuthorization,
    /// Salt used to generate the EOA.
    pub salt: u8,
    /// Initialization calls.
    pub init_calls: Vec<Call>,
}

impl PREPAccount {
    /// Initializes a new account with the given delegation and digest.
    ///
    /// The digest is a hash of the [`UserOp`] used to initialize the account.
    ///
    /// This generates a new EOA address and a signed authorization for the account using the
    /// Provably Rootless EIP-7702 Proxy method, which is an application of Nick's Method to
    /// EIP-7702.
    ///
    /// The authorization item is the signed tuple `(0, delegation, 0)`, where `r` is derived by
    /// taking the lower 160 bits of the hash of the initialization data, `s` is the hash of
    /// `r`, and `y_parity` is always `0`.
    ///
    /// The `r` value is used as an integrity check in the smart contract to prevent front running,
    /// and the `s` value being the hash of `r` should reasonably prove that the private key is
    /// unknown.
    ///
    /// Finding the associated private key for the signature would take `2^159` operations given the
    /// predefined prefix (or trillions of years with the most powerful supercomputers available
    /// today).
    ///
    /// See <https://blog.biconomy.io/prep-deep-dive/>
    pub fn initialize(delegation: Address, init_calls: Vec<Call>) -> Self {
        let digest = Self::calculate_digest(&init_calls);

        // we mine until we have a valid `r`, `s` combination
        let mut salt = [0u8; 32];
        loop {
            let mut hasher = Keccak256::new();
            hasher.update(digest);
            hasher.update(salt);
            let hash: U256 = hasher.finalize().into();

            // Take only the lower 160bits
            let r: U256 = (hash << 96) >> 96;
            let s = keccak256(r.to_be_bytes::<32>());

            let signed_authorization = SignedAuthorization::new_unchecked(
                Authorization { chain_id: U256::ZERO, address: delegation, nonce: 0 },
                0,
                r,
                s.into(),
            );

            if let Ok(eoa) = signed_authorization.recover_authority() {
                return Self { address: eoa, signed_authorization, salt: salt[31], init_calls };
            }

            // u8 should be enough to find it.
            salt[31] += 1;
        }
    }

    /// Returns the expected PREP digest from a list of [`Call`].
    fn calculate_digest(calls: &[Call]) -> B256 {
        let mut hashed_calls = Vec::with_capacity(calls.len());
        let mut target_padded = [0u8; 32];
        for call in calls {
            target_padded[12..].copy_from_slice(call.to.as_slice());

            let mut hasher = Keccak256::new();
            hasher.update(call.eip712_type_hash().as_slice());
            hasher.update(target_padded);
            hasher.update(call.value.to_be_bytes::<32>());
            hasher.update(keccak256(&call.data));
            hashed_calls.push(hasher.finalize());
        }

        keccak256(hashed_calls.abi_encode_packed())
    }

    /// Return the ABI encoded `initData`.
    pub fn init_data(&self) -> Bytes {
        PREPInitData {
            calls: self.init_calls.clone(),
            saltAndDelegation: self.salt_and_delegation().abi_encode_packed().into(),
        }
        .abi_encode_params()
        .into()
    }

    /// Return `saltAndDelegation`.
    ///
    /// `saltAndDelegation` is `bytes32((uint256(salt) << 160) | uint160(delegation))`.
    fn salt_and_delegation(&self) -> B256 {
        let mut salt_and_delegation = [0u8; 32];
        salt_and_delegation[11] = self.salt;
        salt_and_delegation[12..].copy_from_slice(self.signed_authorization.address.as_slice());
        B256::from(salt_and_delegation)
    }

    /// Verifies that the current account is valid.
    pub fn is_valid(&self) -> bool {
        self == &Self::initialize(self.signed_authorization.address, self.init_calls.clone())
    }

    /// Return the list of authorized keys as [`AuthorizeKeyResponse`].
    pub fn authorized_keys(&self) -> Vec<AuthorizeKeyResponse> {
        self.init_calls
            .iter()
            .filter(|call| call.to == Address::ZERO)
            .filter_map(|call| {
                let authorize = authorizeCall::abi_decode(&call.data).ok()?;
                Some(AuthorizeKeyResponse {
                    hash: authorize.key.key_hash(),
                    authorize_key: AuthorizeKey {
                        key: authorize.key,
                        permissions: vec![],
                        signature: None,
                    },
                })
            })
            .collect()
    }
}

sol! {
    struct PREPInitData {
        Call[] calls;
        bytes saltAndDelegation;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{
        primitives::{address, b256, bytes},
        uint,
    };

    const INIT_CALLS: [Call; 2] = [
        Call {
            to: address!("0x100000000000000000636f6e736F6c652E6C6f67"),
            value: uint!(2000000000000000000_U256),
            data: bytes!(
                "0xcebfe33600000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004024c8e0b2b31a1f91f54334f27e04c1aac5b5f0bad187ce4394080477c7c3424952b6c9019ff4c7abe65658e46cc544d7cbd1b591402bf14bc4b94753c65942a0"
            ),
        },
        Call {
            to: address!("0x200000000000000000636f6e736F6c652E6C6f67"),
            value: uint!(4000000000000000000_U256),
            data: bytes!(
                "0xcebfe33600000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004024c8e0b2b31a1f91f54334f27e04c1aac5b5f0bad187ce4394080477c7c3424952b6c9019ff4c7abe65658e46cc544d7cbd1b591402bf14bc4b94753c65942a0"
            ),
        },
    ];

    #[test]
    fn initialize_solidity() {
        struct Case {
            target: Address,
            target_salt: u8,
            delegation: Address,
            digest: B256,
            salt_and_delegation: Bytes,
            init_data: Bytes,
        }

        let cases = [Case {
            target: address!("0xce2b4b648ba29b5ba6fb739ecf25ec36f082a08d"),
            target_salt: 4u8,
            delegation: address!("0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9"),
            digest: b256!("0x4d395bfc5ea4edf4801a023c61aa43c295ab95392a2ab9a894bf2854490c3c72"),
            salt_and_delegation: bytes!(
                "0x0000000000000000000000045991a2df15a8f6a256d3ec51e99254cd3fb576a9"
            ),
            init_data: bytes!(
                "0x000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000003e00000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001e0000000000000000000000000100000000000000000636f6e736f6c652e6c6f670000000000000000000000000000000000000000000000001bc16d674ec8000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000104cebfe33600000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004024c8e0b2b31a1f91f54334f27e04c1aac5b5f0bad187ce4394080477c7c3424952b6c9019ff4c7abe65658e46cc544d7cbd1b591402bf14bc4b94753c65942a000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000636f6e736f6c652e6c6f670000000000000000000000000000000000000000000000003782dace9d90000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000104cebfe33600000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004024c8e0b2b31a1f91f54334f27e04c1aac5b5f0bad187ce4394080477c7c3424952b6c9019ff4c7abe65658e46cc544d7cbd1b591402bf14bc4b94753c65942a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000045991a2df15a8f6a256d3ec51e99254cd3fb576a9"
            ),
        }];

        for Case { target, target_salt, delegation, digest, salt_and_delegation, init_data } in
            cases
        {
            let acc = PREPAccount::initialize(delegation, INIT_CALLS.to_vec());
            assert_eq!(digest, PREPAccount::calculate_digest(&INIT_CALLS));
            assert_eq!(target, acc.address);
            assert_eq!(target_salt, acc.salt);
            assert_eq!(&salt_and_delegation, acc.salt_and_delegation().as_slice());
            assert_eq!(init_data, acc.init_data());
        }
    }
}
