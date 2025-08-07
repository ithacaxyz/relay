//! Token Metadata Caching
//!
//! This module implements caching for ERC20/ERC721/ERC1155 token metadata
//! (name, symbol, decimals) to avoid repeated RPC calls for immutable data.

use alloy::primitives::{Address, ChainId};
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

/// Key for token metadata cache entries
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct TokenKey {
    /// Token contract address
    pub address: Address,
    /// Chain ID where token exists
    pub chain_id: ChainId,
}

impl TokenKey {
    /// Create a new token key
    pub fn new(address: Address, chain_id: ChainId) -> Self {
        Self { address, chain_id }
    }
    
    /// Create token key from asset type (requires token address for non-native assets)
    pub fn from_asset_type(asset_type: &AssetType, token: Option<Address>, chain_id: ChainId) -> Option<Self> {
        match asset_type {
            AssetType::Native => None, // Native tokens don't have contract metadata
            _ => token.map(|addr| Self::new(addr, chain_id)),
        }
    }
}

/// Token metadata information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenMetadata {
    /// Token name (e.g., "Wrapped Ether")
    pub name: String,
    /// Token symbol (e.g., "WETH")
    pub symbol: String,
    /// Token decimals (for ERC20, typically 18)
    pub decimals: u8,
}

/// Token type classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TokenType {
    /// ERC20 fungible token
    ERC20,
    /// ERC721 non-fungible token
    ERC721,
    /// ERC1155 multi-token
    ERC1155,
    /// Unknown or custom token type
    Unknown,
}

impl TokenMetadata {
    /// Create new token metadata
    pub fn new(name: String, symbol: String, decimals: u8) -> Self {
        Self {
            name,
            symbol,
            decimals,
        }
    }
    
    /// Create metadata for ERC20 token (convenience method)
    pub fn erc20(name: String, symbol: String, decimals: u8) -> Self {
        Self::new(name, symbol, decimals)
    }
    
    /// Create metadata for ERC721 token (convenience method)
    pub fn erc721(name: String, symbol: String) -> Self {
        Self::new(name, symbol, 0) // NFTs don't have decimals
    }
    
    /// Create metadata for ERC1155 token (convenience method)
    pub fn erc1155(name: String, symbol: String) -> Self {
        Self::new(name, symbol, 0) // Multi-tokens typically don't have decimals
    }
    
    /// Check if this is a fungible token (has meaningful decimals)
    pub fn is_fungible(&self) -> bool {
        self.decimals > 0
    }
    
    /// Get display name for the token
    pub fn display_name(&self) -> &str {
        if self.name.is_empty() {
            &self.symbol
        } else {
            &self.name
        }
    }
}

/// Cache for token metadata
#[derive(Clone)]
pub struct TokenCache {
    cache: RelayCache<TokenKey, TokenMetadata>,
}

impl TokenCache {
    /// Create a new token cache with default configuration
    ///
    /// Default configuration:
    /// - TTL: 24 hours (86400 seconds) - metadata is immutable
    /// - Max entries: 10000
    pub fn new() -> Self {
        Self::with_config(Duration::from_secs(86400), 10000)
    }
    
    /// Create a new token cache with custom configuration
    pub fn with_config(ttl: Duration, max_entries: u64) -> Self {
        Self {
            cache: RelayCache::new("token_metadata", max_entries, ttl),
        }
    }
    
    /// Get token metadata, using cache if available
    pub async fn get_metadata<F, Fut>(
        &self,
        address: Address,
        chain_id: ChainId,
        fetcher: F,
    ) -> Result<TokenMetadata, RelayError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<TokenMetadata, RelayError>>,
    {
        let key = TokenKey::new(address, chain_id);
        self.cache.get_or_fetch(key, fetcher).await
    }
    
    /// Get or fetch token metadata using a key
    pub async fn get_or_fetch<F, Fut>(
        &self,
        key: TokenKey,
        fetcher: F,
    ) -> Result<TokenMetadata, RelayError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<TokenMetadata, RelayError>>,
    {
        self.cache.get_or_fetch(key, fetcher).await
    }
    
    /// Get token name
    pub async fn get_name<F, Fut>(
        &self,
        address: Address,
        chain_id: ChainId,
        fetcher: F,
    ) -> Result<String, RelayError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<TokenMetadata, RelayError>>,
    {
        let metadata = self.get_metadata(address, chain_id, fetcher).await?;
        Ok(metadata.name)
    }
    
    /// Get token symbol
    pub async fn get_symbol<F, Fut>(
        &self,
        address: Address,
        chain_id: ChainId,
        fetcher: F,
    ) -> Result<String, RelayError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<TokenMetadata, RelayError>>,
    {
        let metadata = self.get_metadata(address, chain_id, fetcher).await?;
        Ok(metadata.symbol)
    }
    
    /// Get token decimals
    pub async fn get_decimals<F, Fut>(
        &self,
        address: Address,
        chain_id: ChainId,
        fetcher: F,
    ) -> Result<u8, RelayError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<TokenMetadata, RelayError>>,
    {
        let metadata = self.get_metadata(address, chain_id, fetcher).await?;
        Ok(metadata.decimals)
    }
    
    /// Get multiple token metadata efficiently
    pub async fn get_many_metadata<F, Fut>(
        &self,
        tokens: Vec<(Address, ChainId)>,
        fetcher: F,
    ) -> Result<Vec<(Address, ChainId, TokenMetadata)>, RelayError>
    where
        F: FnOnce(Vec<(Address, ChainId)>) -> Fut,
        Fut: Future<Output = Result<Vec<(Address, ChainId, TokenMetadata)>, RelayError>>,
    {
        let mut results = Vec::new();
        let mut missing = Vec::new();
        
        // Check cache for each token
        for (address, chain_id) in tokens {
            let key = TokenKey::new(address, chain_id);
            if let Some(metadata) = self.cache.cache.get(&key).await {
                results.push((address, chain_id, metadata));
            } else {
                missing.push((address, chain_id));
            }
        }
        
        // Fetch missing entries
        if !missing.is_empty() {
            let fetched = fetcher(missing).await?;
            
            // Cache the fetched results
            for (address, chain_id, metadata) in &fetched {
                let key = TokenKey::new(*address, *chain_id);
                self.cache.cache.insert(key, metadata.clone()).await;
            }
            
            results.extend(fetched);
        }
        
        Ok(results)
    }
    
    /// Pre-populate cache with known token metadata
    ///
    /// This can be used to warm the cache with well-known tokens
    /// to improve performance on first requests.
    pub async fn populate(&self, address: Address, chain_id: ChainId, metadata: TokenMetadata) {
        let key = TokenKey::new(address, chain_id);
        self.cache.cache.insert(key, metadata).await;
    }
    
    /// Pre-populate cache with multiple tokens
    pub async fn populate_many(&self, tokens: Vec<(Address, ChainId, TokenMetadata)>) {
        for (address, chain_id, metadata) in tokens {
            self.populate(address, chain_id, metadata).await;
        }
    }
    
    /// Invalidate metadata for a specific token (rarely needed since metadata is immutable)
    pub async fn invalidate_token(&self, address: Address, chain_id: ChainId) {
        let key = TokenKey::new(address, chain_id);
        self.cache.invalidate(&key).await;
    }
    
    /// Clear all cached metadata for a specific chain
    pub async fn invalidate_chain(&self, _chain_id: ChainId) {
        // For now, clear entire cache since we don't have efficient
        // chain-specific invalidation. This is rarely needed since
        // token metadata is immutable.
        self.cache.clear().await;
    }
    
    /// Clear all cached token metadata
    pub async fn clear(&self) {
        self.cache.clear().await;
    }
    
    /// Get cache statistics
    pub fn stats(&self) -> crate::cache::CacheStats {
        self.cache.stats()
    }
}

impl Default for TokenCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration for token metadata cache
#[derive(Debug, Clone)]
pub struct TokenCacheConfig {
    /// TTL for token metadata entries in seconds
    pub ttl_seconds: u64,
    /// Maximum number of cached entries
    pub max_entries: u64,
    /// Whether to enable batch fetching optimization
    pub enable_batch_fetching: bool,
    /// Whether to pre-populate with known tokens
    pub enable_preload: bool,
}

impl Default for TokenCacheConfig {
    fn default() -> Self {
        Self {
            ttl_seconds: 86400,            // 24 hours TTL (metadata is immutable)
            max_entries: 10000,            // Cache up to 10k tokens
            enable_batch_fetching: true,   // Enable batch optimization
            enable_preload: true,          // Pre-load well-known tokens
        }
    }
}

impl TokenCacheConfig {
    /// Convert to Duration
    pub fn ttl(&self) -> Duration {
        Duration::from_secs(self.ttl_seconds)
    }
    
    /// Create TokenCache from this config
    pub fn build(&self) -> TokenCache {
        TokenCache::with_config(self.ttl(), self.max_entries)
    }
}

/// Well-known token addresses for pre-population
pub struct WellKnownTokens;

impl WellKnownTokens {
    /// Get well-known tokens for Ethereum mainnet
    pub fn ethereum_mainnet() -> Vec<(Address, TokenMetadata)> {
        vec![
            // WETH
            (
                "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".parse().unwrap(),
                TokenMetadata::erc20("Wrapped Ether".to_string(), "WETH".to_string(), 18),
            ),
            // USDC
            (
                "0xA0b86a33E6441119f80e23c44A5e0B5eE4f0Fe6e".parse().unwrap(),
                TokenMetadata::erc20("USD Coin".to_string(), "USDC".to_string(), 6),
            ),
            // USDT
            (
                "0xdAC17F958D2ee523a2206206994597C13D831ec7".parse().unwrap(),
                TokenMetadata::erc20("Tether USD".to_string(), "USDT".to_string(), 6),
            ),
            // DAI
            (
                "0x6B175474E89094C44Da98b954EedeAC495271d0F".parse().unwrap(),
                TokenMetadata::erc20("Dai Stablecoin".to_string(), "DAI".to_string(), 18),
            ),
        ]
    }
    
    /// Pre-populate cache with well-known tokens for a chain
    pub async fn preload_chain(cache: &TokenCache, chain_id: ChainId) {
        let tokens = match chain_id {
            1 => Self::ethereum_mainnet(),
            _ => vec![], // Add other chains as needed
        };
        
        for (address, metadata) in tokens {
            cache.populate(address, chain_id, metadata).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    
    #[tokio::test]
    async fn test_token_cache_basic() {
        let cache = TokenCache::new();
        let token = Address::random();
        let chain_id = 1u64;
        let metadata = TokenMetadata::erc20("Test Token".to_string(), "TEST".to_string(), 18);
        
        let fetch_count = std::sync::Arc::new(AtomicU64::new(0));
        
        // First call should fetch
        let count_clone = fetch_count.clone();
        let meta_clone = metadata.clone();
        let result1 = cache.get_metadata(
            token,
            chain_id,
            || async move {
                count_clone.fetch_add(1, Ordering::SeqCst);
                Ok(meta_clone)
            }
        ).await.unwrap();
        
        assert_eq!(result1.name, "Test Token");
        assert_eq!(result1.symbol, "TEST");
        assert_eq!(result1.decimals, 18);
        assert_eq!(fetch_count.load(Ordering::SeqCst), 1);
        
        // Second call should use cache
        let count_clone = fetch_count.clone();
        let result2 = cache.get_metadata(
            token,
            chain_id,
            || async move {
                count_clone.fetch_add(1, Ordering::SeqCst);
                Ok(TokenMetadata::erc20("Different".to_string(), "DIFF".to_string(), 8))
            }
        ).await.unwrap();
        
        assert_eq!(result2.name, "Test Token"); // Should return cached value
        assert_eq!(fetch_count.load(Ordering::SeqCst), 1); // No additional fetch
    }
    
    #[tokio::test]
    async fn test_token_cache_individual_fields() {
        let cache = TokenCache::new();
        let token = Address::random();
        let chain_id = 1u64;
        let metadata = TokenMetadata::erc20("My Token".to_string(), "MYT".to_string(), 8);
        
        // Test name
        let name = cache.get_name(
            token,
            chain_id,
            || async { Ok(metadata.clone()) }
        ).await.unwrap();
        assert_eq!(name, "My Token");
        
        // Test symbol (should use cache)
        let symbol = cache.get_symbol(
            token,
            chain_id,
            || async { Ok(TokenMetadata::erc20("Wrong".to_string(), "WRONG".to_string(), 18)) }
        ).await.unwrap();
        assert_eq!(symbol, "MYT"); // Should use cached value
        
        // Test decimals (should use cache)
        let decimals = cache.get_decimals(
            token,
            chain_id,
            || async { Ok(TokenMetadata::erc20("Wrong".to_string(), "WRONG".to_string(), 18)) }
        ).await.unwrap();
        assert_eq!(decimals, 8); // Should use cached value
    }
    
    #[tokio::test]
    async fn test_token_metadata_types() {
        // ERC20
        let erc20 = TokenMetadata::erc20("Token".to_string(), "TKN".to_string(), 18);
        assert_eq!(erc20.token_type, TokenType::ERC20);
        assert!(erc20.is_fungible());
        
        // ERC721
        let erc721 = TokenMetadata::erc721("NFT".to_string(), "NFT".to_string());
        assert_eq!(erc721.token_type, TokenType::ERC721);
        assert!(!erc721.is_fungible());
        assert_eq!(erc721.decimals, 0);
        
        // ERC1155
        let erc1155 = TokenMetadata::erc1155("Multi".to_string(), "MULTI".to_string());
        assert_eq!(erc1155.token_type, TokenType::ERC1155);
        assert!(!erc1155.is_fungible());
        assert_eq!(erc1155.decimals, 0);
    }
    
    #[tokio::test]
    async fn test_token_cache_populate() {
        let cache = TokenCache::new();
        let token = Address::random();
        let chain_id = 1u64;
        let metadata = TokenMetadata::erc20("Pre-loaded".to_string(), "PRE".to_string(), 12);
        
        // Pre-populate
        cache.populate(token, chain_id, metadata.clone()).await;
        
        // Should return pre-populated value without calling fetcher
        let result = cache.get_metadata(
            token,
            chain_id,
            || async { panic!("Should not be called!") }
        ).await.unwrap();
        
        assert_eq!(result.name, "Pre-loaded");
        assert_eq!(result.symbol, "PRE");
        assert_eq!(result.decimals, 12);
    }
    
    #[tokio::test]
    async fn test_token_key_from_asset_type() {
        let token = Address::random();
        let chain_id = 1u64;
        
        // ERC20
        let erc20_asset = AssetType::ERC20;
        let erc20_key = TokenKey::from_asset_type(&erc20_asset, Some(token), chain_id).unwrap();
        assert_eq!(erc20_key.address, token);
        assert_eq!(erc20_key.chain_id, chain_id);
        
        // Native (should return None)
        let native_asset = AssetType::Native;
        let native_key = TokenKey::from_asset_type(&native_asset, None, chain_id);
        assert!(native_key.is_none());
        
        // ERC721
        let erc721_asset = AssetType::ERC721;
        let erc721_key = TokenKey::from_asset_type(&erc721_asset, Some(token), chain_id).unwrap();
        assert_eq!(erc721_key.address, token);
    }
    
    #[tokio::test]
    async fn test_well_known_tokens() {
        let ethereum_tokens = WellKnownTokens::ethereum_mainnet();
        
        // Should have some well-known tokens
        assert!(!ethereum_tokens.is_empty());
        
        // Check WETH
        let weth = ethereum_tokens.iter()
            .find(|(_, meta)| meta.symbol == "WETH")
            .expect("WETH should be in well-known tokens");
        
        assert_eq!(weth.1.name, "Wrapped Ether");
        assert_eq!(weth.1.decimals, 18);
        assert!(weth.1.is_fungible());
    }
}