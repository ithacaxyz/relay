use alloy::{
    primitives::{Address, U256},
    providers::Provider,
    rpc::types::state::StateOverride,
    sol,
    transports::{TransportErrorKind, TransportResult},
};
use tracing::debug;
use Delegation::DelegationInstance;

sol! {
    #[sol(rpc)]
    contract Delegation {
        address public constant ENTRY_POINT;

        /// Returns the nonce salt.
        function nonceSalt() public view virtual returns (uint256);
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

    /// Get the nonce salt for this account.
    pub async fn nonce_salt(&self) -> TransportResult<U256> {
        debug!(eoa = %self.delegation.address(), "Fetching nonce salt");
        let nonce_salt = self
            .delegation
            .nonceSalt()
            .call()
            .overrides(&self.overrides)
            .await
            .map_err(TransportErrorKind::custom)?
            ._0;
        debug!(
            eoa = %self.delegation.address(),
            "Fetched nonce salt {}",
            nonce_salt
        );

        Ok(nonce_salt)
    }
}
