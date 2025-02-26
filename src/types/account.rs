use Delegation::DelegationInstance;
use alloy::{
    eips::eip7702::SignedAuthorization,
    primitives::{Address, B256, Keccak256, U256},
    providers::Provider,
    rpc::types::{Authorization, state::StateOverride},
    sol,
    transports::{TransportErrorKind, TransportResult},
};
use tracing::debug;

sol! {
    #[sol(rpc)]
    contract Delegation {
        address public constant ENTRY_POINT;

        /// A spend period.
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

/// Initializes a new account with the given delegation and digest.
///
/// The digest is a hash of the [`UserOp`] used to initialize the account.
///
/// This generates a new EOA address and a signed authorization for the account using the Provably
/// Rootless EIP-7702 Proxy method, which is an application of Nick's Method to EIP-7702.
///
/// The authorization item is the signed tuple `(0, delegation, 0)`, where `r` is the hash of the
/// initialization data, `s` is a random value with a predefined prefix, and `y_parity` is always
/// `0`.
///
/// The `r` value is used as an integrity check in the smart contract to prevent front running, and
/// the `s` value uses a 20-byte prefix to reasonably prove that the private key is unknown.
///
/// Finding the associated private key for the signature would take `2^159` operations given the
/// predefined prefix (or trillions of years with the most powerful supercomputers available
/// today).
///
/// See <https://blog.biconomy.io/prep-deep-dive/>
pub fn initialize(delegation: Address, digest: B256) -> (Address, SignedAuthorization) {
    let random_s: U256 = B256::random().into();

    // we mine until we have a valid `r`, `s` combination
    let mut i: u64 = 0;
    loop {
        let mut hasher = Keccak256::new();
        hasher.update(digest);
        hasher.update(i.to_be_bytes());
        let hash = hasher.finalize();

        let auth = SignedAuthorization::new_unchecked(
            Authorization { chain_id: U256::ZERO, address: delegation, nonce: 0 },
            0,
            hash.into(),
            // note: the 20 byte prefix more than ensures `s` is always within `secp256kn/2`.
            random_s >> 160,
        );

        if let Ok(eoa) = auth.recover_authority() {
            return (eoa, auth);
        }

        i += 1;
    }
}
