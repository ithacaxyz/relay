use super::Call;
use Delegation::DelegationInstance;
use alloy::{
    eips::eip7702::SignedAuthorization,
    primitives::{Address, B256, Keccak256, U256, keccak256},
    providers::Provider,
    rpc::types::{Authorization, state::StateOverride},
    sol,
    sol_types::{SolStruct, SolValue},
    transports::{TransportErrorKind, TransportResult},
};
use serde::{Deserialize, Serialize};
use tracing::debug;

sol! {
    #[sol(rpc)]
    contract Delegation {
        address public constant ENTRY_POINT;

        /// A spend period.
        #[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
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
    }
}

/// A Porto account.
#[derive(Debug)]
pub struct Account<P: Provider> {
    delegation: DelegationInstance<(), P>,
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

    /// Sets overrides for all calls on this account.
    pub fn with_overrides(mut self, overrides: StateOverride) -> Self {
        self.overrides = overrides;
        self
    }

    /// Get the entrypoint address for this account.
    pub async fn entrypoint(&self) -> TransportResult<Address> {
        debug!(eoa = %self.delegation.address(), "Fetching entrypoint");
        let entrypoint = self
            .delegation
            .ENTRY_POINT()
            .call()
            .overrides(&self.overrides)
            .await
            .map_err(TransportErrorKind::custom)?;
        debug!(
            eoa = %self.delegation.address(),
            entrypoint = %entrypoint.ENTRY_POINT,
            "Fetched entrypoint"
        );

        Ok(entrypoint.ENTRY_POINT)
    }
}

/// PREP account based on <https://blog.biconomy.io/prep-deep-dive/>.
///
/// Read [`PREPAccount::initialize`] for more information on how it is generated.
#[derive(Debug, Clone)]
pub struct PREPAccount {
    /// EOA generated address.
    pub address: Address,
    /// Signed 7702 authorization.
    pub signed_authorization: SignedAuthorization,
    /// Salt used to generate the EOA.
    pub salt: u8,
    /// Initialization calls.
    pub init_data: Vec<Call>,
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
    pub fn initialize(delegation: Address, init_data: Vec<Call>) -> Self {
        let digest = Self::calculate_digest(&init_data);

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
                return Self { address: eoa, signed_authorization, salt: salt[31], init_data };
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
            target_padded[12..].copy_from_slice(call.target.as_slice());

            let mut hasher = Keccak256::new();
            hasher.update(call.eip712_type_hash().as_slice());
            hasher.update(target_padded);
            hasher.update(call.value.to_be_bytes::<32>());
            hasher.update(keccak256(&call.data));
            hashed_calls.push(hasher.finalize());
        }

        keccak256(hashed_calls.abi_encode_packed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{address, b256, bytes};

    // #[test]
    // fn initialize_prep() {
    //     let cases = [(Address::ZERO, B256::ZERO), (Address::random(), B256::random())];

    //     for (address, digest) in cases {
    //         PREPAccount::initialize(address, digest);
    //     }
    // }

    // #[test]
    // fn initialize_solidity() {
    //     struct Case {
    //         target: Address,
    //         target_salt: u8,
    //         delegation: Address,
    //         digest: B256,
    //     }

    //     let cases = [Case {
    //         target: address!("0xfE1D536604feB43A980dA073161B7cF09F3fd969"),
    //         target_salt: 0u8,
    //         delegation: address!("0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9"),
    //         digest: b256!("0x16f3f8d8870eecad098c9634fa7e635e4bb8526f633e0f3333b5627de0626a23"),
    //     }];

    //     for Case { target, target_salt, delegation, digest } in cases {
    //         let acc = PREPAccount::initialize(delegation, digest);
    //         assert_eq!((target, target_salt), (acc.address, acc.salt))
    //     }
    // }

    #[test]
    fn prep_digest() {
        assert_eq!(
            PREPAccount::calculate_digest(&[
                Call {
                    target: address!("0x100000000000000000636f6e736F6c652E6C6f67"),
                    value: U256::from(2_000_000_000_000_000_000u64),
                    data: bytes!(
                        "0xcebfe33600000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004024c8e0b2b31a1f91f54334f27e04c1aac5b5f0bad187ce4394080477c7c3424952b6c9019ff4c7abe65658e46cc544d7cbd1b591402bf14bc4b94753c65942a0"
                    )
                },
                Call {
                    target: address!("0x200000000000000000636f6e736F6c652E6C6f67"),
                    value: U256::from(4_000_000_000_000_000_000u64),
                    data: bytes!(
                        "0xcebfe33600000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004024c8e0b2b31a1f91f54334f27e04c1aac5b5f0bad187ce4394080477c7c3424952b6c9019ff4c7abe65658e46cc544d7cbd1b591402bf14bc4b94753c65942a0"
                    )
                }
            ]),
            b256!("0x7d758e41b107c29709e836a1519a50e1d848efbdc99192330685086158f3655d")
        );
    }
}
