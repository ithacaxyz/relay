//! LayerZero test environment setup utilities
//!
//! This module provides utilities for setting up LayerZero in test environments,
//! including multi-chain deployment, endpoint configuration, and relayer integration.

use super::{
    interfaces::IEndpointV2Mock,
    relayer::{ChainEndpoint, LayerZeroRelayer},
    wire_escrows,
};
use crate::e2e::{
    constants::DEPLOYER_ADDRESS,
    environment::{Environment, deploy_contract},
};
use alloy::{
    primitives::{Address, U256},
    providers::{Provider, ext::AnvilApi},
    sol_types::SolValue,
};
use eyre::{Result, WrapErr};
use futures_util::{future::try_join_all, try_join};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::task::JoinHandle;

/// LayerZero configuration for cross-chain communication
///
/// Note: All vectors follow the same indexing as Environment.providers
/// i.e., endpoints[0] corresponds to the endpoint on chain 0 (env.providers[0])
#[derive(Debug, Clone)]
pub struct LayerZeroConfig {
    /// Endpoint addresses for each chain (indexed by chain)
    pub endpoints: Vec<Address>,
    /// Escrow addresses for each chain (indexed by chain)
    pub escrows: Vec<Address>,
    /// Chain EIDs (Endpoint IDs) for each chain (indexed by chain)
    pub eids: Vec<u32>,
}

/// Result of deploying LayerZero contracts on a single chain
#[derive(Debug, Clone)]
pub struct LayerZeroDeployment {
    /// EndpointV2Mock contract address
    pub endpoint: Address,
    /// MockEscrow contract address
    pub escrow: Address,
    /// MinimalSendReceiveLib contract address
    pub library: Address,
}

/// Extension trait for Environment to add LayerZero functionality
pub trait LayerZeroEnvironment {
    /// Sets up a multi-chain test environment with LayerZero support.
    async fn setup_multi_chain_with_layerzero(num_chains: usize) -> Result<Environment>;

    /// Starts the LayerZero relayer for automatic cross-chain message delivery.
    async fn start_layerzero_relayer(&self) -> Result<Vec<JoinHandle<Result<()>>>>;

    /// Get LayerZero configuration.
    fn layerzero_config(&self) -> &LayerZeroConfig;
}

impl LayerZeroEnvironment for Environment {
    /// Sets up a multi-chain test environment with LayerZero support.
    ///
    /// This method:
    /// 1. Sets up the base multi-chain environment
    /// 2. Deploys LayerZero mocks on each chain (EndpointV2Mock, MinimalSendReceiveLib, MockEscrow)
    /// 3. Wires the endpoints and escrows for cross-chain communication
    /// 4. Funds the escrows with ETH for gas
    async fn setup_multi_chain_with_layerzero(num_chains: usize) -> Result<Self> {
        if num_chains < 2 {
            eyre::bail!("LayerZero setup requires at least 2 chains");
        }

        // Set up base multi-chain environment
        let mut env = Self::setup_multi_chain(num_chains).await?;

        // Deploy LayerZero contracts on all chains
        let layerzero_deployments =
            try_join_all(env.providers.iter().enumerate().map(|(index, provider)| {
                let layerzero_contracts_path = PathBuf::from(
                    std::env::var("LAYERZERO_CONTRACTS")
                        .unwrap_or_else(|_| "tests/e2e/layerzero/contracts/out".to_string()),
                );
                let eid = 101 + index as u32; // EIDs start from 101

                async move {
                    deploy_layerzero_contracts(provider, &layerzero_contracts_path, eid)
                        .await
                        .wrap_err(format!("Failed to deploy LayerZero contracts on chain {index}"))
                }
            }))
            .await?;

        let eids: Vec<u32> = (0..num_chains).map(|i| 101 + i as u32).collect();

        // Configure all endpoint libraries now that we have all EIDs
        try_join_all(layerzero_deployments.iter().enumerate().map(async |(i, deployment)| {
            configure_endpoint_libraries_for_all_chains(
                &env.providers[i],
                deployment.endpoint,
                deployment.library,
                eids[i],
                &eids,
            )
            .await
            .wrap_err(format!("Failed to configure endpoint libraries for chain {i}"))
        }))
        .await?;

        // Wire endpoints and escrows between all chain pairs
        try_join_all((0..num_chains).flat_map(|i| ((i + 1)..num_chains).map(move |j| (i, j))).map(
            async |(i, j)| {
                wire_escrows(
                    &env.providers[i],
                    &env.providers[j],
                    layerzero_deployments[i].escrow,
                    layerzero_deployments[j].escrow,
                    eids[i],
                    eids[j],
                )
                .await
                .wrap_err(format!("Failed to wire escrows between chains {i} and {j}"))
            },
        ))
        .await?;

        // Mine blocks to ensure all wiring transactions are included
        try_join_all(
            (0..num_chains)
                .filter(|&i| env.anvils[i].is_some())
                .map(async |i| env.providers[i].anvil_mine(Some(1), None).await),
        )
        .await?;

        // Store LayerZero config - extract addresses for storage
        let endpoints: Vec<Address> = layerzero_deployments.iter().map(|d| d.endpoint).collect();
        let escrows: Vec<Address> = layerzero_deployments.iter().map(|d| d.escrow).collect();
        env.settlement.layerzero = Some(LayerZeroConfig { endpoints, escrows, eids });

        Ok(env)
    }

    /// Starts the LayerZero relayer for automatic cross-chain message delivery.
    ///
    /// This method automatically:
    /// - Uses all available LayerZero endpoints from the environment
    /// - Builds ChainEndpoint structs with the correct EIDs
    /// - Starts monitoring tasks for all configured chains
    ///
    /// # Returns
    ///
    /// Returns a vector of join handles for the monitoring tasks.
    ///
    /// # Panics
    ///
    /// This method panics if LayerZero was not configured during setup.
    async fn start_layerzero_relayer(&self) -> Result<Vec<JoinHandle<Result<()>>>> {
        // Get LayerZero configuration
        let lz_config = self.layerzero_config();

        // Build ChainEndpoint structs from LayerZero config
        // Note: chain_index matches Environment.providers index
        let endpoints: Vec<ChainEndpoint> = (0..self.num_chains())
            .map(|i| ChainEndpoint {
                chain_index: i,
                endpoint: lz_config.endpoints[i],
                eid: lz_config.eids[i],
            })
            .collect();

        // Create and start the relayer
        let relayer = Arc::new(LayerZeroRelayer::new(endpoints, self.get_rpc_urls()?).await?);
        let handles = relayer.start().await?;

        // Allow time for subscription setup
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        Ok(handles)
    }

    /// Get LayerZero configuration.
    ///
    /// # Panics
    ///
    /// This method panics if LayerZero was not configured during setup.
    fn layerzero_config(&self) -> &LayerZeroConfig {
        self.settlement.layerzero
            .as_ref()
            .expect("LayerZero not configured. Use setup_multi_chain_with_layerzero() to enable LayerZero support.")
    }
}

/// Deploy LayerZero contracts (EndpointV2Mock, MockEscrow, Library)
async fn deploy_layerzero_contracts<P: Provider>(
    provider: &P,
    contracts_path: &Path,
    eid: u32,
) -> Result<LayerZeroDeployment> {
    // Deploy EndpointV2Mock with the EID and owner

    let endpoint = deploy_contract(
        provider,
        &contracts_path.join("EndpointV2Mock.sol/EndpointV2Mock.json"),
        Some(SolValue::abi_encode(&(eid, DEPLOYER_ADDRESS)).into()),
    )
    .await
    .wrap_err("Failed to deploy EndpointV2Mock")?;

    // Deploy minimal send/receive library for the endpoint
    let lib = deploy_contract(
        provider,
        &contracts_path.join("MinimalSendReceiveLib.sol/MinimalSendReceiveLib.json"),
        None,
    )
    .await
    .wrap_err("Failed to deploy MinimalSendReceiveLib")?;

    // Deploy MockEscrow with the endpoint address and owner
    let escrow = deploy_contract(
        provider,
        &contracts_path.join("MockEscrow.sol/MockEscrow.json"),
        Some(SolValue::abi_encode(&(endpoint, DEPLOYER_ADDRESS)).into()),
    )
    .await?;

    // Return deployment result
    Ok(LayerZeroDeployment { endpoint, escrow, library: lib })
}

/// Configures endpoint libraries for LayerZero for all chains
async fn configure_endpoint_libraries_for_all_chains<P: Provider>(
    provider: &P,
    endpoint: Address,
    lib: Address,
    current_eid: u32,
    all_eids: &[u32],
) -> Result<()> {
    let endpoint_contract = IEndpointV2Mock::new(endpoint, provider);

    // Register the library
    endpoint_contract.registerLibrary(lib).send().await?.get_receipt().await?;

    // Set default libraries for all other chains
    try_join_all(all_eids.iter().filter(|&&eid| eid != current_eid).map(async |&dst_eid| {
        try_join!(
            async {
                let tx = endpoint_contract
                    .setDefaultSendLibrary(dst_eid, lib)
                    .send()
                    .await
                    .map_err(eyre::Error::from)?;
                tx.get_receipt().await.map_err(eyre::Error::from)
            },
            async {
                let tx = endpoint_contract
                    .setDefaultReceiveLibrary(dst_eid, lib, U256::ZERO)
                    .send()
                    .await
                    .map_err(eyre::Error::from)?;
                tx.get_receipt().await.map_err(eyre::Error::from)
            }
        )?;
        Ok::<_, eyre::Error>(())
    }))
    .await?;

    Ok(())
}
