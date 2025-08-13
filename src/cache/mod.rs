//! Caching infrastructure for RPC performance optimization

use alloy::{
    eips::eip1559::Eip1559Estimation,
    primitives::{Address, B256, ChainId, U256},
};
use moka::future::Cache;
use std::{sync::Arc, time::Duration};

use crate::types::CoinKind;

/// Cache for RPC-related data to reduce redundant calls
#[derive(Clone, Debug)]
pub struct RelayCache {
    /// Cache for gas estimates per chain (TTL: 5 seconds)
    gas_estimates: Arc<Cache<ChainId, Eip1559Estimation>>,
    /// Cache for ETH prices (TTL: 10 seconds)
    eth_prices: Arc<Cache<CoinKind, U256>>,
    /// Cache for asset balances (TTL: 2 seconds)
    asset_balances: Arc<Cache<(Address, ChainId, Address), U256>>,
    /// Cache for simulation results (TTL: 10 seconds)
    simulation_cache: Arc<Cache<B256, SimulationResult>>,
}

/// Result of a transaction simulation
#[derive(Clone, Debug)]
pub struct SimulationResult {
    /// Asset differences from the simulation
    pub asset_diffs: Vec<AssetDiff>,
    /// Quote for the transaction
    pub quote: Quote,
}

/// Asset difference information
#[derive(Clone, Debug)]
pub struct AssetDiff {
    /// Chain ID where the asset change occurs
    pub chain_id: ChainId,
    /// Address of the asset
    pub address: Address,
    /// Amount of the asset change
    pub amount: U256,
}

/// Transaction quote information
#[derive(Clone, Debug)]
pub struct Quote {
    /// Fee for the transaction
    pub fee: U256,
    /// Gas limit for the transaction
    pub gas_limit: u64,
}

impl RelayCache {
    /// Create a new cache instance with default TTL settings
    pub fn new() -> Self {
        Self {
            gas_estimates: Arc::new(
                Cache::builder().time_to_live(Duration::from_secs(5)).max_capacity(100).build(),
            ),
            eth_prices: Arc::new(
                Cache::builder().time_to_live(Duration::from_secs(10)).max_capacity(50).build(),
            ),
            asset_balances: Arc::new(
                Cache::builder().time_to_live(Duration::from_secs(2)).max_capacity(1000).build(),
            ),
            simulation_cache: Arc::new(
                Cache::builder().time_to_live(Duration::from_secs(10)).max_capacity(500).build(),
            ),
        }
    }

    /// Get cached gas estimate for a chain
    pub async fn get_gas_estimate(&self, chain_id: ChainId) -> Option<Eip1559Estimation> {
        self.gas_estimates.get(&chain_id).await
    }

    /// Cache gas estimate for a chain
    pub async fn cache_gas_estimate(&self, chain_id: ChainId, estimate: Eip1559Estimation) {
        self.gas_estimates.insert(chain_id, estimate).await;
    }

    /// Get cached ETH price
    pub async fn get_eth_price(&self, coin: CoinKind) -> Option<U256> {
        self.eth_prices.get(&coin).await
    }

    /// Cache ETH price
    pub async fn cache_eth_price(&self, coin: CoinKind, price: U256) {
        self.eth_prices.insert(coin, price).await;
    }

    /// Get cached asset balance
    pub async fn get_asset_balance(
        &self,
        account: Address,
        chain_id: ChainId,
        asset: Address,
    ) -> Option<U256> {
        self.asset_balances.get(&(account, chain_id, asset)).await
    }

    /// Cache asset balance
    pub async fn cache_asset_balance(
        &self,
        account: Address,
        chain_id: ChainId,
        asset: Address,
        balance: U256,
    ) {
        self.asset_balances.insert((account, chain_id, asset), balance).await;
    }

    /// Get cached simulation result
    pub async fn get_simulation(&self, key: B256) -> Option<SimulationResult> {
        self.simulation_cache.get(&key).await
    }

    /// Cache simulation result
    pub async fn cache_simulation(&self, key: B256, result: SimulationResult) {
        self.simulation_cache.insert(key, result).await;
    }

    /// Create cache key for simulation
    pub fn simulation_key(intent: &[u8], overrides: &[u8]) -> B256 {
        use alloy::primitives::keccak256;
        let mut data = Vec::new();
        data.extend_from_slice(intent);
        data.extend_from_slice(overrides);
        keccak256(&data)
    }
}

impl Default for RelayCache {
    fn default() -> Self {
        Self::new()
    }
}
