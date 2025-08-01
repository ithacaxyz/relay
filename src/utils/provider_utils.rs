//! Provider access utilities and common patterns.

use crate::{chains::Chains, error::RelayError};
use alloy::{primitives::{Address, ChainId}, providers::{DynProvider, Provider}};

/// Provider access utilities for common patterns.
#[derive(Debug)]
pub struct ProviderUtils;

impl ProviderUtils {
    /// Get a provider for the specified chain ID from chains.
    ///
    /// This is a utility wrapper around the common pattern of getting a provider
    /// and handling the error case when a chain is not supported.
    pub fn get_provider(chains: &Chains, chain_id: ChainId) -> Result<DynProvider, RelayError> {
        chains
            .get(chain_id)
            .ok_or(RelayError::UnsupportedChain(chain_id))
            .map(|chain| chain.provider.clone())
    }

    /// Get transaction count for an address on the specified chain.
    ///
    /// Common pattern used for nonce management and validation.
    pub async fn get_transaction_count(
        chains: &Chains,
        chain_id: ChainId,
        address: Address,
    ) -> Result<u64, RelayError> {
        let provider = Self::get_provider(chains, chain_id)?;
        provider.get_transaction_count(address).await.map_err(RelayError::from)
    }
}