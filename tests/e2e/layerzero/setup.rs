//! LayerZero test environment setup utilities
//!
//! This module provides utilities for setting up LayerZero in test environments,
//! including multi-chain deployment, endpoint configuration, and relayer integration.

use super::{
    relayer::{ChainEndpoint, IEndpointV2Mock, LayerZeroRelayer},
    wire_escrows,
};
use crate::e2e::environment::{Environment, deploy_contract};
use alloy::{
    network::EthereumWallet,
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder, WalletProvider, ext::AnvilApi},
    rpc::client::ClientBuilder,
    sol_types::SolValue,
};
use eyre::{Result, WrapErr};
use futures_util::future::try_join_all;
use relay::{signers::DynSigner, spawn::RETRY_LAYER};
use std::{
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};
use tokio::task::JoinHandle;

/// LayerZero configuration for cross-chain communication
#[derive(Debug, Clone)]
pub struct LayerZeroConfig {
    /// Endpoint addresses for each chain
    pub endpoints: Vec<Address>,
    /// Escrow addresses for each chain
    pub escrows: Vec<Address>,
    /// Chain EIDs (Endpoint IDs)
    pub eids: Vec<u32>,
}

/// Extension trait for Environment to add LayerZero functionality
pub trait LayerZeroEnvironment {
    /// Sets up a multi-chain test environment with LayerZero support.
    async fn setup_multi_chain_with_layerzero(num_chains: usize) -> Result<Environment>;

    /// Starts the LayerZero relayer for automatic cross-chain message delivery.
    async fn start_layerzero_relayer(&self) -> Result<Vec<JoinHandle<Result<()>>>>;

    /// Get LayerZero configuration.
    fn layerzero_config(&self) -> &LayerZeroConfig;

    /// Store LayerZero configuration.
    fn set_layerzero_config(&mut self, config: LayerZeroConfig);
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

        // Get the deployer signer to create providers with the correct signer
        let deployer_priv = "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6";
        let deployer = DynSigner::from_signing_key(deployer_priv)
            .await
            .wrap_err("Deployer signer load failed")?;

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

        // Extract addresses
        let endpoints: Vec<Address> = layerzero_deployments.iter().map(|d| d.0).collect();
        let escrows: Vec<Address> = layerzero_deployments.iter().map(|d| d.1).collect();
        let libs: Vec<Address> = layerzero_deployments.iter().map(|d| d.2).collect();
        let eids: Vec<u32> = (0..num_chains).map(|i| 101 + i as u32).collect();

        // Configure all endpoint libraries now that we have all EIDs
        for i in 0..num_chains {
            configure_endpoint_libraries_for_all_chains(
                &env.providers[i],
                endpoints[i],
                libs[i],
                eids[i],
                &eids,
            )
            .await?;
        }

        // Wire endpoints and escrows between all chain pairs
        for i in 0..num_chains {
            for j in (i + 1)..num_chains {
                // Wire endpoints - not required for manual delivery tests
                // The mock endpoints don't require explicit wiring

                // Wire escrows between chains
                let (provider1, provider2) =
                    create_providers_for_escrow_wiring(&env, i, j, &deployer).await?;

                wire_escrows(&provider1, &provider2, escrows[i], escrows[j], eids[i], eids[j])
                    .await
                    .wrap_err(format!("Failed to wire escrows between chains {i} and {j}"))?;
            }
        }

        // Mine blocks to ensure all wiring transactions are included
        for i in 0..num_chains {
            if let Some(_anvil) = &env.anvils[i] {
                env.providers[i].anvil_mine(Some(1), None).await?;
            }
        }

        // Note: Escrows are funded during actual cross-chain operations as needed

        // Store LayerZero config
        env.set_layerzero_config(LayerZeroConfig { endpoints, escrows, eids });

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
        let endpoints: Vec<ChainEndpoint> = (0..self.num_chains())
            .map(|i| ChainEndpoint {
                chain_index: i,
                endpoint: lz_config.endpoints[i],
                eid: lz_config.eids[i],
            })
            .collect();

        // Get RPC URLs for all chains
        let rpc_urls = self.get_rpc_urls()?;

        // Create and start the relayer
        let relayer = Arc::new(LayerZeroRelayer::new(endpoints, rpc_urls));
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
        self.layerzero
            .as_ref()
            .expect("LayerZero not configured. Use setup_multi_chain_with_layerzero() to enable LayerZero support.")
    }

    /// Store LayerZero configuration.
    fn set_layerzero_config(&mut self, config: LayerZeroConfig) {
        self.layerzero = Some(config);
    }
}

/// Deploy LayerZero contracts (EndpointV2Mock, MockEscrow, Library)
async fn deploy_layerzero_contracts<P: Provider>(
    provider: &P,
    contracts_path: &Path,
    eid: u32,
) -> Result<(Address, Address, Address)> {
    // Deploy EndpointV2Mock with the EID and owner
    const DEPLOYER_ADDRESS: &str = "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720";
    let deployer_address = Address::from_str(DEPLOYER_ADDRESS).unwrap();

    let endpoint = deploy_contract(
        provider,
        &contracts_path.join("EndpointV2Mock.sol/EndpointV2Mock.json"),
        Some(SolValue::abi_encode(&(eid, deployer_address)).into()),
    )
    .await
    .wrap_err("Failed to deploy EndpointV2Mock")?;

    // Deploy minimal send/receive library for the endpoint

    // Deploy the MinimalSendReceiveLib
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
        Some(SolValue::abi_encode(&(endpoint, deployer_address)).into()),
    )
    .await?;

    // Return endpoint, escrow, and library addresses
    Ok((endpoint, escrow, lib))
}

/// Creates providers with deployer wallet for escrow wiring
pub async fn create_providers_for_escrow_wiring(
    env: &Environment,
    chain1_index: usize,
    chain2_index: usize,
    deployer: &DynSigner,
) -> Result<(impl Provider + WalletProvider, impl Provider + WalletProvider)> {
    let endpoint1 = if let Some(anvil) = &env.anvils[chain1_index] {
        anvil.endpoint_url().to_string()
    } else {
        std::env::var("TEST_EXTERNAL_ANVIL")
            .wrap_err("TEST_EXTERNAL_ANVIL not set for external anvil")?
    };

    let endpoint2 = if let Some(anvil) = &env.anvils[chain2_index] {
        anvil.endpoint_url().to_string()
    } else {
        std::env::var("TEST_EXTERNAL_ANVIL")
            .wrap_err("TEST_EXTERNAL_ANVIL not set for external anvil")?
    };

    let client1 =
        ClientBuilder::default().layer(RETRY_LAYER.clone()).connect(endpoint1.as_str()).await?;
    let provider1 = ProviderBuilder::new()
        .wallet(EthereumWallet::from(deployer.0.clone()))
        .connect_client(client1);

    let client2 =
        ClientBuilder::default().layer(RETRY_LAYER.clone()).connect(endpoint2.as_str()).await?;
    let provider2 = ProviderBuilder::new()
        .wallet(EthereumWallet::from(deployer.0.clone()))
        .connect_client(client2);

    Ok((provider1, provider2))
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
    for &dst_eid in all_eids {
        if dst_eid != current_eid {
            endpoint_contract
                .setDefaultSendLibrary(dst_eid, lib)
                .send()
                .await?
                .get_receipt()
                .await?;

            endpoint_contract
                .setDefaultReceiveLibrary(dst_eid, lib, U256::ZERO)
                .send()
                .await?
                .get_receipt()
                .await?;
        }
    }

    Ok(())
}
