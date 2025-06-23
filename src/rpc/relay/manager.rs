use crate::{
    asset::AssetInfoServiceHandle,
    chains::Chains,
    config::QuoteConfig,
    error::{AuthError, RelayError},
    price::PriceOracle,
    storage::StorageApi,
    types::{Account, FeeTokens, VersionedContracts},
};
use alloy::{
    eips::eip7702::constants::EIP7702_DELEGATION_DESIGNATOR,
    primitives::{Address, Bytes, ChainId},
    providers::{DynProvider, Provider},
    rpc::types::state::StateOverridesBuilder,
};
use tracing::instrument;

#[async_trait::async_trait]
pub trait Manager {
    /// Get chains
    fn chains(&self) -> &Chains;

    /// Get contracts
    fn contracts(&self) -> &VersionedContracts;

    /// Get orchestrator address
    fn orchestrator(&self) -> Address {
        self.contracts().orchestrator.address
    }

    /// Previously deployed orchestrators.
    fn legacy_orchestrators(&self) -> impl Iterator<Item = Address> {
        self.contracts().legacy_orchestrators.iter().map(|c| c.address)
    }

    /// Get delegation implementation address
    fn delegation_implementation(&self) -> Address {
        self.contracts().delegation_implementation.address
    }

    /// Previously deployed delegation implementations.
    fn legacy_delegations(&self) -> impl Iterator<Item = Address> {
        self.contracts().legacy_delegations.iter().map(|c| c.address)
    }

    /// The simulator address.
    fn simulator(&self) -> Address {
        self.contracts().simulator.address
    }

    /// Get fee recipient
    fn fee_recipient(&self) -> Address;

    /// Get priority fee percentile
    fn priority_fee_percentile(&self) -> f64;

    /// Get quote config
    fn quote_config(&self) -> &QuoteConfig;

    /// Get fee tokens
    fn fee_tokens(&self) -> &FeeTokens;

    /// Get price oracle
    fn price_oracle(&self) -> &PriceOracle;

    /// Get asset info
    fn asset_info(&self) -> &AssetInfoServiceHandle;

    /// Get storage
    fn storage(&self) -> &dyn StorageApi;

    /// Get a provider for the given chain ID
    fn provider(&self, chain_id: ChainId) -> Result<DynProvider, RelayError> {
        self.chains()
            .get(chain_id)
            .map(|chain| chain.provider.clone())
            .ok_or(RelayError::UnsupportedChain(chain_id))
    }

    /// Checks if the orchestrator is supported.
    fn is_supported_orchestrator(&self, orchestrator: &Address) -> bool {
        self.orchestrator() == *orchestrator
            || self.legacy_orchestrators().any(|c| c == *orchestrator)
    }

    /// Checks if the account has a supported delegation implementation. If so, returns it.
    async fn has_supported_delegation<P: Provider + Clone>(
        &self,
        account: &Account<P>,
    ) -> Result<Address, RelayError> {
        let address = self.get_delegation_implementation(account).await?;
        if self.delegation_implementation() == address
            || self.legacy_delegations().any(|c| c == address)
        {
            return Ok(address);
        }
        Err(AuthError::InvalidDelegation(address).into())
    }

    /// Ensures the account has the latest delegation implementation. Otherwise, returns error.
    async fn ensure_latest_delegation<P: Provider + Clone>(
        &self,
        account: &Account<P>,
    ) -> Result<(), RelayError> {
        let address = self.has_supported_delegation(account).await?;
        if self.delegation_implementation() != address {
            return Err(AuthError::InvalidDelegation(address).into());
        }
        Ok(())
    }

    /// Returns the delegation implementation address from the requested account.
    ///
    /// It will return error if the delegation proxy is invalid.
    #[instrument(skip_all)]
    async fn get_delegation_implementation<P: Provider + Clone>(
        &self,
        account: &Account<P>,
    ) -> Result<Address, RelayError> {
        if let Some(delegation) = account.delegation_implementation().await? {
            return Ok(delegation);
        }

        // Attempt to retrieve the delegation proxy from storage, since it might not be
        // deployed yet.
        let Some(stored) = self.storage().read_account(&account.address()).await? else {
            return Err(RelayError::Auth(AuthError::EoaNotDelegated(account.address()).boxed()));
        };

        let address = account.address();
        let account = account.clone().with_overrides(
            StateOverridesBuilder::default()
                .with_code(
                    address,
                    Bytes::from(
                        [
                            &EIP7702_DELEGATION_DESIGNATOR,
                            stored.signed_authorization.address().as_slice(),
                        ]
                        .concat(),
                    ),
                )
                .build(),
        );

        account.delegation_implementation().await?.ok_or_else(|| {
            RelayError::Auth(
                AuthError::InvalidDelegationProxy(*stored.signed_authorization.address()).boxed(),
            )
        })
    }
}
