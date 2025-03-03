use Delegation::DelegationInstance;
use alloy::{
    eips::eip7702::SignedAuthorization,
    primitives::{Address, B256, Keccak256, U256, keccak256},
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
/// The authorization item is the signed tuple `(0, delegation, 0)`, where `r` is derived by taking
/// the lower 160 bits of the hash of the initialization data, `s` is the hash of `r`, and
/// `y_parity` is always `0`.
///
/// The `r` value is used as an integrity check in the smart contract to prevent front running, and
/// the `s` value being the hash of `r` should reasonably prove that the private key is unknown.
///
/// Finding the associated private key for the signature would take `2^159` operations given the
/// predefined prefix (or trillions of years with the most powerful supercomputers available
/// today).
///
/// See <https://blog.biconomy.io/prep-deep-dive/>
pub fn initialize(delegation: Address, digest: B256) -> (Address, SignedAuthorization, u8) {
    // we mine until we have a valid `r`, `s` combination
    let mut salt = [0u8; 32];
    loop {
        let mut hasher = Keccak256::new();
        hasher.update(digest);
        hasher.update(salt);
        let hash = hasher.finalize();

        let pre_r: U256 = hash.into();
        let r: U256 = (pre_r << 96) >> 96;
        let s = keccak256(r.to_be_bytes::<32>());

        let auth = SignedAuthorization::new_unchecked(
            Authorization { chain_id: U256::ZERO, address: delegation, nonce: 0 },
            0,
            r,
            s.into(),
        );

        if let Ok(eoa) = auth.recover_authority() {
            return (eoa, auth, salt[31]);
        }

        // u8 should be enough to find it.
        salt[31] += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{address, b256};

    #[test]
    fn initialize_prep() {
        let cases = [(Address::ZERO, B256::ZERO), (Address::random(), B256::random())];

        for (address, digest) in cases {
            initialize(address, digest);
        }
    }

    #[test]
    fn initialize_solidity() {
        struct Case {
            target: Address,
            target_salt: u8,
            delegation: Address,
            digest: B256,
        }

        let cases = [Case {
            target: address!("0xfE1D536604feB43A980dA073161B7cF09F3fd969"),
            target_salt: 0u8,
            delegation: address!("0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9"),
            digest: b256!("0x16f3f8d8870eecad098c9634fa7e635e4bb8526f633e0f3333b5627de0626a23"),
        }];

        for Case { target, target_salt, delegation, digest } in cases {
            let (prep_eoa, _, prep_salt) = initialize(delegation, digest);
            assert_eq!((target, target_salt), (prep_eoa, prep_salt))
        }
    }
}
