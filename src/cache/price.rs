//! Price Oracle Caching
//!
//! This module implements caching for price oracle data to reduce external API calls
//! to services like CoinGecko. Prices are cached with a 5-minute TTL (300 seconds) which
//! provides a good balance between data freshness and cache efficiency for fee estimation.

use alloy::primitives::{Address, ChainId, U256};
use std::{
    hash::Hash,
    future::Future,
    time::Duration,
};
use serde::{Deserialize, Serialize};
use crate::{
    cache::RelayCache,
    error::RelayError,
    types::AssetType,
};

/// Key for price cache entries
///
/// Combines token address, chain ID, and optionally block number to create
/// a unique cache key for price data.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct PriceKey {
    /// Token address (or native token marker)
    pub token: Address,
    /// Chain ID where token exists
    pub chain_id: ChainId,
    /// Block number for historical prices (None for latest)
    pub block_number: Option<u64>,
}

impl PriceKey {
    /// Create a new price key for current prices
    pub fn current(token: Address, chain_id: ChainId) -> Self {
        Self {
            token,
            chain_id,
            block_number: None,
        }
    }
    
    /// Create a new price key for historical prices at a specific block
    pub fn at_block(token: Address, chain_id: ChainId, block_number: u64) -> Self {
        Self {
            token,
            chain_id,
            block_number: Some(block_number),
        }
    }
    
    /// Create price key from asset type
    pub fn from_asset_type(asset_type: &AssetType, token: Address, chain_id: ChainId, block_number: Option<u64>) -> Self {
        // For native tokens, use zero address; for others use the provided token address
        let token_addr = match asset_type {
            AssetType::Native => Address::ZERO,
            _ => token,
        };
        
        Self {
            token: token_addr,
            chain_id,
            block_number,
        }
    }
}

/// Price cache implementation for ETH price data
///
/// Caches ETH prices for different tokens/chains with a configurable TTL.
/// Designed to work with the existing PriceOracle infrastructure.
#[derive(Clone)]
pub struct PriceCache {
    cache: RelayCache<PriceKey, U256>,
}

impl PriceCache {
    /// Create a new price cache with default configuration
    ///
    /// Default configuration:
    /// - TTL: 300 seconds (5 minutes) - optimized for fee estimation where slight staleness is acceptable
    /// - Max entries: 1000
    pub fn new() -> Self {
        Self::with_config(Duration::from_secs(300), 1000)
    }
    
    /// Create a new price cache with custom configuration
    pub fn with_config(ttl: Duration, max_entries: u64) -> Self {
        Self {
            cache: RelayCache::new("price_oracle", max_entries, ttl),
        }
    }
    
    /// Get ETH price for a token, using cache if available
    ///
    /// This method implements the cache-aside pattern:
    /// 1. Check cache for existing price
    /// 2. If not found, execute the fetcher to get price from oracle
    /// 3. Cache the result for future requests
    pub async fn get_eth_price<F, Fut>(
        &self,
        key: PriceKey,
        fetcher: F,
    ) -> Result<U256, RelayError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<U256, RelayError>>,
    {
        self.cache.get_or_fetch(key, fetcher).await
    }
    
    /// Get ETH price for a token with current block
    pub async fn get_current_eth_price<F, Fut>(
        &self,
        token: Address,
        chain_id: ChainId,
        fetcher: F,
    ) -> Result<U256, RelayError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<U256, RelayError>>,
    {
        let key = PriceKey::current(token, chain_id);
        self.get_eth_price(key, fetcher).await
    }
    
    /// Get historical ETH price for a token at specific block
    pub async fn get_historical_eth_price<F, Fut>(
        &self,
        token: Address,
        chain_id: ChainId,
        block_number: u64,
        fetcher: F,
    ) -> Result<U256, RelayError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<U256, RelayError>>,
    {
        let key = PriceKey::at_block(token, chain_id, block_number);
        self.get_eth_price(key, fetcher).await
    }
    
    /// Get ETH price using asset type
    pub async fn get_asset_eth_price<F, Fut>(
        &self,
        asset_type: &AssetType,
        chain_id: ChainId,
        block_number: Option<u64>,
        fetcher: F,
    ) -> Result<U256, RelayError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<U256, RelayError>>,
    {
        // For this method, we need a token address - use ZERO for native
        let token = match asset_type {
            AssetType::Native => Address::ZERO,
            _ => Address::ZERO, // Default to ZERO for now
        };
        let key = PriceKey::from_asset_type(asset_type, token, chain_id, block_number);
        self.get_eth_price(key, fetcher).await
    }
    
    /// Invalidate price cache for a specific token/chain
    pub async fn invalidate_token(&self, token: Address, chain_id: ChainId) {
        // Invalidate both current and any historical prices
        // Note: This is a simplified invalidation - in practice we might want
        // to track all keys for more precise invalidation
        let current_key = PriceKey::current(token, chain_id);
        self.cache.invalidate(&current_key).await;
    }
    
    /// Invalidate all cached prices for a specific chain
    pub async fn invalidate_chain(&self, chain_id: ChainId) {
        // Use Moka's scan functionality to find and invalidate entries for the specific chain
        let cache = self.cache.inner();
        
        // Collect keys to invalidate (we need to collect first to avoid iterator invalidation)
        let keys_to_invalidate: Vec<PriceKey> = cache
            .iter()
            .filter_map(|(key, _)| {
                if key.chain_id == chain_id {
                    Some((*key).clone())
                } else {
                    None
                }
            })
            .collect();
        
        // Invalidate each key for the specific chain
        let invalidated_count = keys_to_invalidate.len();
        for key in keys_to_invalidate {
            cache.invalidate(&key).await;
        }
        
        tracing::debug!(
            cache = "price_oracle",
            chain_id = chain_id,
            invalidated_count = invalidated_count,
            "Invalidated chain-specific price cache entries"
        );
    }
    
    /// Clear all cached prices
    pub async fn clear(&self) {
        self.cache.clear().await;
    }
    
    /// Get cache statistics
    pub fn stats(&self) -> crate::cache::CacheStats {
        self.cache.stats()
    }
}

impl Default for PriceCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration for price cache
#[derive(Debug, Clone)]
pub struct PriceCacheConfig {
    /// TTL for price entries in seconds
    pub ttl_seconds: u64,
    /// Maximum number of cached entries
    pub max_entries: u64,
    /// Whether to cache historical prices (at specific blocks)
    pub cache_historical: bool,
}

impl Default for PriceCacheConfig {
    fn default() -> Self {
        Self {
            ttl_seconds: 60,           // 1 minute TTL
            max_entries: 1000,         // Cache up to 1000 price entries
            cache_historical: true,    // Cache historical prices by default
        }
    }
}

impl PriceCacheConfig {
    /// Convert to Duration
    pub fn ttl(&self) -> Duration {
        Duration::from_secs(self.ttl_seconds)
    }
    
    /// Create PriceCache from this config
    pub fn build(&self) -> PriceCache {
        PriceCache::with_config(self.ttl(), self.max_entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    
    #[tokio::test]
    async fn test_price_cache_basic() {
        let cache = PriceCache::new();
        let token = Address::random();
        let chain_id = 1u64;
        let price = U256::from(1000);
        
        let fetch_count = std::sync::Arc::new(AtomicU64::new(0));
        
        // First call should fetch
        let count_clone = fetch_count.clone();
        let result1 = cache.get_current_eth_price(
            token,
            chain_id,
            || async move {
                count_clone.fetch_add(1, Ordering::SeqCst);
                Ok(price)
            }
        ).await.unwrap();
        
        assert_eq!(result1, price);
        assert_eq!(fetch_count.load(Ordering::SeqCst), 1);
        
        // Second call should use cache
        let count_clone = fetch_count.clone();
        let result2 = cache.get_current_eth_price(
            token,
            chain_id,
            || async move {
                count_clone.fetch_add(1, Ordering::SeqCst);
                Ok(U256::from(2000)) // Different price
            }
        ).await.unwrap();
        
        assert_eq!(result2, price); // Should return cached price
        assert_eq!(fetch_count.load(Ordering::SeqCst), 1); // No additional fetch
    }
    
    #[tokio::test]
    async fn test_price_cache_historical() {
        let cache = PriceCache::new();
        let token = Address::random();
        let chain_id = 1u64;
        let block_number = 12345u64;
        let price = U256::from(1500);
        
        // Cache historical price
        let result = cache.get_historical_eth_price(
            token,
            chain_id,
            block_number,
            || async move { Ok(price) }
        ).await.unwrap();
        
        assert_eq!(result, price);
        
        // Verify current and historical are separate cache entries
        let current_price = U256::from(2000);
        let result2 = cache.get_current_eth_price(
            token,
            chain_id,
            || async move { Ok(current_price) }
        ).await.unwrap();
        
        assert_eq!(result2, current_price);
        
        // Historical should still be cached
        let result3 = cache.get_historical_eth_price(
            token,
            chain_id,
            block_number,
            || async move { Ok(U256::from(9999)) } // Should not be called
        ).await.unwrap();
        
        assert_eq!(result3, price); // Should return cached historical price
    }
    
    #[tokio::test]
    async fn test_price_key_creation() {
        let token = Address::random();
        let chain_id = 1u64;
        let block_number = 12345u64;
        
        // Current price key
        let current_key = PriceKey::current(token, chain_id);
        assert_eq!(current_key.token, token);
        assert_eq!(current_key.chain_id, chain_id);
        assert_eq!(current_key.block_number, None);
        
        // Historical price key
        let historical_key = PriceKey::at_block(token, chain_id, block_number);
        assert_eq!(historical_key.token, token);
        assert_eq!(historical_key.chain_id, chain_id);
        assert_eq!(historical_key.block_number, Some(block_number));
        
        // Keys should be different
        assert_ne!(current_key, historical_key);
    }
    
    #[tokio::test]
    async fn test_price_cache_invalidation() {
        let cache = PriceCache::new();
        let token = Address::random();
        let chain_id = 1u64;
        let price1 = U256::from(1000);
        let price2 = U256::from(2000);
        
        // Cache initial price
        let result1 = cache.get_current_eth_price(
            token,
            chain_id,
            || async move { Ok(price1) }
        ).await.unwrap();
        assert_eq!(result1, price1);
        
        // Verify cached
        let result2 = cache.get_current_eth_price(
            token,
            chain_id,
            || async move { Ok(U256::from(9999)) } // Should not be called
        ).await.unwrap();
        assert_eq!(result2, price1);
        
        // Invalidate
        cache.invalidate_token(token, chain_id).await;
        
        // Should fetch new price
        let result3 = cache.get_current_eth_price(
            token,
            chain_id,
            || async move { Ok(price2) }
        ).await.unwrap();
        assert_eq!(result3, price2);
    }
}