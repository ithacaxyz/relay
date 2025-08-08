//! Nonce management module.
//!
//! This module provides functionality for managing nonces in the relay system.
//!
//! Nonces are used to ensure that each transaction is unique and prevent replay attacks.

use std::sync::Arc;

use alloy::{
    primitives::{Address, ChainId},
    providers::fillers::NonceManager,
};
use async_trait::async_trait;
use dashmap::DashMap;
use futures_util::lock::Mutex;

/// [`MultiChainNonceManager`] is a nonce manager that can handle multiple chains and addresses.
///
/// It is based on [`CachedNonceManager`] and provides a convenient way to manage nonces for
/// multiple chains and addresses.
#[derive(Clone, Debug, Default)]
pub struct MultiChainNonceManager {
    #[allow(clippy::type_complexity)]
    nonces: Arc<DashMap<(ChainId, Address), Arc<Mutex<u64>>>>,
}

#[async_trait]
impl NonceManager for MultiChainNonceManager {
    async fn get_next_nonce<P, N>(
        &self,
        provider: &P,
        address: Address,
    ) -> alloy::transports::TransportResult<u64>
    where
        P: alloy::providers::Provider<N>,
        N: alloy::network::Network,
    {
        // Use `u64::MAX` as a sentinel value to indicate that the nonce has not been fetched yet.
        const NONE: u64 = u64::MAX;

        let chain_id = provider.get_chain_id().await?;

        // Locks dashmap internally for a short duration to clone the `Arc`.
        // We also don't want to hold the dashmap lock through the await point below.
        let nonce = {
            let rm = self
                .nonces
                .entry((chain_id, address))
                .or_insert_with(|| Arc::new(Mutex::new(NONE)));
            Arc::clone(rm.value())
        };

        let mut nonce = nonce.lock().await;
        let new_nonce = if *nonce == NONE {
            // Initialize the nonce if we haven't seen this account before.
            provider.get_transaction_count(address).pending().await?
        } else {
            *nonce + 1
        };
        *nonce = new_nonce;
        Ok(new_nonce)
    }
}
