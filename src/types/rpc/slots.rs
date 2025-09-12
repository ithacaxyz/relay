use alloy::{
    contract::StorageSlotFinder,
    primitives::{Address, B256, ChainId},
    providers::Provider,
    rpc::types::TransactionRequest,
};
use dashmap::DashMap;
use std::sync::Arc;

use crate::error::RelayError;

/// Key for identifying a specific ERC20 balance slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BalanceSlotKey {
    /// The chain ID where the token exists.
    pub chain_id: ChainId,
    /// The token contract address.
    pub token: Address,
    /// The account address whose balance we're querying.
    pub account: Address,
}

impl BalanceSlotKey {
    /// Creates a new balance slot key.
    pub fn new(chain_id: ChainId, token: Address, account: Address) -> Self {
        Self { chain_id, token, account }
    }
}

/// Cache for ERC20 balance storage slots.
/// 
/// This cache stores the storage slot locations for ERC20 balance mappings,
/// keyed by [`BalanceSlotKey`].
#[derive(Clone, Debug)]
pub struct Erc20BalanceSlotCache {
    /// The cache storage: BalanceSlotKey -> storage_slot
    cache: Arc<DashMap<BalanceSlotKey, B256>>,
}

impl Erc20BalanceSlotCache {
    /// Creates a new empty cache.
    pub fn new() -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
        }
    }

    /// Gets a cached slot if it exists.
    pub fn get(&self, key: BalanceSlotKey) -> Option<B256> {
        self.cache.get(&key).map(|entry| *entry)
    }

    /// Inserts a slot into the cache.
    pub fn insert(&self, key: BalanceSlotKey, slot: B256) {
        self.cache.insert(key, slot);
    }
}

/// Detector for ERC20 balance slots with caching.
#[derive(Clone, Debug)]
pub struct Erc20BalanceSlotDetector {
    cache: Erc20BalanceSlotCache,
}

impl Erc20BalanceSlotDetector {
    /// Creates a new detector with an empty cache.
    pub fn new() -> Self {
        Self {
            cache: Erc20BalanceSlotCache::new(),
        }
    }

    /// Creates a new detector with a provided cache.
    pub fn with_cache(cache: Erc20BalanceSlotCache) -> Self {
        Self { cache }
    }

    /// Finds the storage slot for an ERC20 balance, using cache when available.
    /// 
    /// This method first checks the cache for a previously discovered slot.
    /// If not found, it uses the StorageSlotFinder to discover the slot and caches
    /// the result for future use.
    pub async fn find_slot<P: Provider>(
        &self,
        provider: P,
        chain_id: ChainId,
        token_address: Address,
        account: Address,
    ) -> Result<Option<B256>, RelayError> {
        let key = BalanceSlotKey::new(chain_id, token_address, account);
        
        // Check cache first
        if let Some(slot) = self.cache.get(key) {
            return Ok(Some(slot));
        }

        // Not in cache, find the slot
        let slot = StorageSlotFinder::balance_of(provider, token_address, account)
            // There's an issue with the `eth_createAccesslist` endpoint on at least polygon and BSC
            // where a regular request fails with insufficient funds error.
            // A workaround for this is setting the gas limit field, a `balanceOf` call usually
            // consumes ~31k gas, so 100k should always be sufficient
            .with_request(TransactionRequest::default().gas_limit(100_000))
            .find_slot()
            .await?;

        // Cache the result if found
        if let Some(slot) = slot {
            self.cache.insert(key, slot);
        }

        Ok(slot)
    }
}