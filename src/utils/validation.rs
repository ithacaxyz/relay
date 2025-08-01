//! Common validation utilities and patterns.

use crate::{
    error::{AuthError, RelayError},
    storage::StorageApi,
    types::Account,
};
use alloy::{
    eips::eip7702::constants::EIP7702_DELEGATION_DESIGNATOR,
    primitives::{Address, Bytes},
    providers::Provider,
    rpc::types::state::StateOverridesBuilder,
};

/// Validation utilities for account delegation and common checks.
#[derive(Debug)]
pub struct ValidationUtils;

impl ValidationUtils {
    /// Gets the account's delegation implementation address.
    /// 
    /// First checks if the account already has a delegation implementation deployed.
    /// If not, attempts to retrieve from storage as a fallback.
    pub async fn get_delegation_implementation<P: Provider + Clone>(
        account: &Account<P>,
        storage: &impl StorageApi,
    ) -> Result<Address, RelayError> {
        if let Some(delegation) = account.delegation_implementation().await? {
            return Ok(delegation);
        }
        
        // Attempt to retrieve the delegation proxy from storage, since it might not be
        // deployed yet.
        let Some(stored) = storage.read_account(&account.address()).await? else {
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

    /// Checks if the account has a supported delegation implementation.
    ///
    /// Validates that the delegation implementation is either the current one
    /// or from the list of supported legacy implementations.
    pub async fn has_supported_delegation<P: Provider + Clone>(
        account: &Account<P>,
        storage: &impl StorageApi,
        current_delegation: Address,
        legacy_delegations: &[Address],
    ) -> Result<Address, RelayError> {
        let address = Self::get_delegation_implementation(account, storage).await?;
        
        if current_delegation == address || legacy_delegations.contains(&address) {
            return Ok(address);
        }
        
        Err(AuthError::InvalidDelegation(address).into())
    }

    /// Ensures the account has the latest delegation implementation.
    ///
    /// Returns an error if the account is using an outdated delegation implementation.
    pub async fn ensure_latest_delegation<P: Provider + Clone>(
        account: &Account<P>,
        storage: &impl StorageApi,
        current_delegation: Address,
        legacy_delegations: &[Address],
    ) -> Result<(), RelayError> {
        let address = Self::has_supported_delegation(
            account,
            storage,
            current_delegation,
            legacy_delegations,
        ).await?;
        
        if current_delegation != address {
            return Err(AuthError::InvalidDelegation(address).into());
        }
        
        Ok(())
    }

    /// Validates that an account is properly delegated for relay operations.
    ///
    /// This is a comprehensive check that ensures the account meets all
    /// requirements for participating in relay transactions.
    pub async fn validate_account_delegation<P: Provider + Clone>(
        account: &Account<P>,
        storage: &impl StorageApi,
        current_delegation: Address,
        legacy_delegations: &[Address],
        require_latest: bool,
    ) -> Result<Address, RelayError> {
        if require_latest {
            Self::ensure_latest_delegation(account, storage, current_delegation, legacy_delegations).await?;
            Ok(current_delegation)
        } else {
            Self::has_supported_delegation(account, storage, current_delegation, legacy_delegations).await
        }
    }
}