//! LayerZero test environment setup utilities
//!
//! This module provides utilities for setting up LayerZero in test environments,
//! including multi-chain deployment, endpoint configuration, and relayer integration.

use super::{
    interfaces::IOApp,
    relayer::{ChainEndpoint, LayerZeroRelayer},
    utils::configure_uln_for_endpoint,
    wire_oapps,
};
use crate::e2e::{
    constants::{LAYERZERO_DEPLOYER_ADDRESS, LAYERZERO_DEPLOYER_PRIVATE_KEY},
    environment::{Environment, deploy_contract},
    layerzero::utils::EXECUTOR_ADDRESS,
};
use alloy::{
    network::EthereumWallet,
    primitives::{Address, ChainId, U256},
    providers::{DynProvider, Provider, ProviderBuilder, ext::AnvilApi},
    rpc::client::ClientBuilder,
    signers::local::PrivateKeySigner,
    sol_types::SolValue,
};
use eyre::{Result, WrapErr};
use futures_util::{future::try_join_all, try_join};
use relay::{chains::RETRY_LAYER, interop::settler::layerzero::contracts::ILayerZeroEndpointV2};
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
pub struct LayerZeroTestConfig {
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
    /// LayerZero settler contract address
    pub settler: Address,
    /// MinimalSendReceiveLib contract address
    pub library: Address,
}

/// Extension trait for Environment to add LayerZero functionality
pub trait LayerZeroEnvironment {
    /// Sets up a multi-chain test environment with LayerZero support.
    /// This will deploy LayerZero infrastructure and configure the relay to use LayerZero settler.
    async fn setup_multi_chain_with_layerzero(num_chains: usize) -> Result<Environment>;

    /// Starts the LayerZero relayer for automatic cross-chain message delivery.
    /// Returns the relayer instance and task handles.
    async fn start_layerzero_relayer(
        &self,
    ) -> Result<(LayerZeroRelayer, Vec<JoinHandle<Result<()>>>)>;

    /// Get LayerZero configuration.
    fn layerzero_config(&self) -> &LayerZeroTestConfig;
}

impl LayerZeroEnvironment for Environment {
    /// Sets up a multi-chain test environment with LayerZero support.
    /// This will deploy LayerZero infrastructure and configure the relay to use LayerZero settler.
    async fn setup_multi_chain_with_layerzero(num_chains: usize) -> Result<Self> {
        use crate::e2e::environment::EnvironmentConfig;

        if num_chains < 2 {
            eyre::bail!("LayerZero setup requires at least 2 chains");
        }

        // Set up environment with LayerZero configured for relay (settler)
        let config = EnvironmentConfig { num_chains, use_layerzero: true, ..Default::default() };

        Self::setup_with_config(config).await
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
    async fn start_layerzero_relayer(
        &self,
    ) -> Result<(LayerZeroRelayer, Vec<JoinHandle<Result<()>>>)> {
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
        let relayer =
            LayerZeroRelayer::new(endpoints, self.get_rpc_urls()?, lz_config.escrows.clone())
                .await?;
        let handles = relayer.clone().start().await?;

        // Allow time for subscription setup
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        Ok((relayer, handles))
    }

    /// Get LayerZero configuration.
    ///
    /// # Panics
    ///
    /// This method panics if LayerZero was not configured during setup.
    fn layerzero_config(&self) -> &LayerZeroTestConfig {
        self.settlement.layerzero
            .as_ref()
            .expect("LayerZero not configured. Use setup_multi_chain_with_layerzero() to enable LayerZero support.")
    }
}

/// Deploy LayerZero contracts (EndpointV2Mock, MockEscrow, Settler, Library)
async fn deploy_layerzero_contracts<P: Provider>(
    provider: &P,
    contracts_path: &Path,
    test_contracts_path: &Path,
    eid: u32,
) -> Result<LayerZeroDeployment> {
    // Deploy EndpointV2Mock with the EID and owner
    let endpoint = deploy_contract(
        provider,
        &contracts_path.join("EndpointV2Mock.sol/EndpointV2Mock.json"),
        Some(SolValue::abi_encode(&(eid, LAYERZERO_DEPLOYER_ADDRESS)).into()),
    )
    .await
    .wrap_err("Failed to deploy EndpointV2Mock")?;

    // Deploy minimal send/receive library for the endpoint
    let lib = deploy_contract(
        provider,
        &contracts_path.join("ReceiveUln302Mock.sol/ReceiveUln302Mock.json"),
        Some(SolValue::abi_encode(&(endpoint,)).into()),
    )
    .await
    .wrap_err("Failed to deploy ReceiveUln302Mock")?;

    // Deploy MockEscrow with the endpoint address and owner
    let escrow = deploy_contract(
        provider,
        &contracts_path.join("MockEscrow.sol/MockEscrow.json"),
        Some(SolValue::abi_encode(&(endpoint, LAYERZERO_DEPLOYER_ADDRESS)).into()),
    )
    .await
    .wrap_err("Failed to deploy MockEscrow")?;

    // Deploy LayerZero settler with owner and L0SettlerSigner
    //
    // Constructor: constructor(address _owner, address _l0SettlerSigner)
    let l0_settler_signer = LAYERZERO_DEPLOYER_ADDRESS; // Use deployer as signer for tests
    let settler = deploy_contract(
        provider,
        &test_contracts_path.join("LayerZeroSettler.sol/LayerZeroSettler.json"),
        Some(SolValue::abi_encode(&(LAYERZERO_DEPLOYER_ADDRESS, l0_settler_signer)).into()),
    )
    .await
    .wrap_err("Failed to deploy LayerZeroSettler")?;

    // Return deployment result
    Ok(LayerZeroDeployment { endpoint, escrow, settler, library: lib })
}

/// Configures endpoint libraries for LayerZero for all chains
async fn configure_endpoint_libraries_for_all_chains<P: Provider>(
    provider: &P,
    endpoint: Address,
    lib: Address,
    current_eid: u32,
    all_eids: &[u32],
    oapps: &[Address],
) -> Result<()> {
    let endpoint_contract = ILayerZeroEndpointV2::new(endpoint, provider);
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
        configure_uln_for_endpoint(provider, endpoint, oapps, lib, dst_eid, EXECUTOR_ADDRESS)
            .await?;
        Ok::<_, eyre::Error>(())
    }))
    .await?;

    Ok(())
}

/// Result of LayerZero infrastructure deployment
pub struct LayerZeroInfrastructureDeployment {
    /// Configuration for the relay
    pub relay_config: relay::config::LayerZeroConfig,
    /// Configuration for test environment
    pub test_config: LayerZeroTestConfig,
    /// LayerZero settler addresses for each chain
    pub settlers: Vec<Address>,
}

/// Deploy LayerZero infrastructure on all chains
pub async fn deploy_layerzero_infrastructure(
    providers: &[DynProvider],
    chain_ids: &[ChainId],
    rpc_urls: &[String],
) -> eyre::Result<LayerZeroInfrastructureDeployment> {
    // Create a dedicated signer for LayerZero deployments to ensure consistent addresses
    let layerzero_signer = PrivateKeySigner::from_bytes(&LAYERZERO_DEPLOYER_PRIVATE_KEY)?;
    let layerzero_wallet = EthereumWallet::from(layerzero_signer.clone());

    // Fund the LayerZero deployer on all chains
    for provider in providers {
        provider.anvil_set_balance(layerzero_signer.address(), U256::from(1000e18)).await?;
    }

    // Deploy LayerZero contracts on all chains
    let layerzero_contracts_path = PathBuf::from(
        std::env::var("LAYERZERO_CONTRACTS")
            .unwrap_or_else(|_| "tests/e2e/layerzero/contracts/out".to_string()),
    );

    let eids: Vec<u32> = (0..providers.len()).map(|i| 101 + i as u32).collect();
    let test_contracts_path = PathBuf::from(
        std::env::var("TEST_CONTRACTS").unwrap_or_else(|_| "tests/account/out".to_string()),
    );

    // Create providers with LayerZero wallet for deployment
    let lz_providers: Arc<Vec<DynProvider>> = Arc::new(
        try_join_all(rpc_urls.iter().map(|url| {
            let wallet = layerzero_wallet.clone();
            async move {
                let client = ClientBuilder::default()
                    .layer(RETRY_LAYER.clone())
                    .connect(url.as_str())
                    .await?;
                Ok::<_, eyre::Error>(
                    ProviderBuilder::new().wallet(wallet).connect_client(client).erased(),
                )
            }
        }))
        .await?,
    );

    let layerzero_deployments =
        try_join_all(lz_providers.iter().enumerate().map(|(index, provider)| {
            let eid = eids[index];
            let lz_path = layerzero_contracts_path.clone();
            let test_path = test_contracts_path.clone();
            async move {
                deploy_layerzero_contracts(provider, &lz_path, &test_path, eid)
                    .await
                    .wrap_err(format!("Failed to deploy LayerZero contracts on chain {index}"))
            }
        }))
        .await?;

    // Configure all endpoint and their libraries
    try_join_all(layerzero_deployments.iter().enumerate().map(|(i, deployment)| {
        let eid = eids[i];
        let all_eids = eids.clone();
        let providers = lz_providers.clone();
        async move {
            let _ = IOApp::new(deployment.settler, &providers[i])
                .setEndpoint(deployment.endpoint)
                .send()
                .await?
                .get_receipt()
                .await?;

            configure_endpoint_libraries_for_all_chains(
                &providers[i],
                deployment.endpoint,
                deployment.library,
                eid,
                &all_eids,
                &[deployment.escrow, deployment.settler],
            )
            .await
            .wrap_err(format!("Failed to configure endpoint libraries for chain {i}"))
        }
    }))
    .await?;

    // Wire escrows and settlers between all chain pairs
    let num_providers = lz_providers.len();
    try_join_all(
        (0..num_providers).flat_map(|i| ((i + 1)..num_providers).map(move |j| (i, j))).map(
            |(i, j)| {
                let escrow_i = layerzero_deployments[i].escrow;
                let escrow_j = layerzero_deployments[j].escrow;
                let settler_i = layerzero_deployments[i].settler;
                let settler_j = layerzero_deployments[j].settler;
                let eid_i = eids[i];
                let eid_j = eids[j];
                let providers = lz_providers.clone();
                async move {
                    // Wire escrows
                    wire_oapps(&providers[i], &providers[j], escrow_i, escrow_j, eid_i, eid_j)
                        .await
                        .wrap_err(format!("Failed to wire escrows between chains {i} and {j}"))?;

                    // Wire settlers (using same function as escrows)
                    wire_oapps(&providers[i], &providers[j], settler_i, settler_j, eid_i, eid_j)
                        .await
                        .wrap_err(format!("Failed to wire settlers between chains {i} and {j}"))
                }
            },
        ),
    )
    .await?;

    // Prepare the configuration
    let endpoints: Vec<Address> = layerzero_deployments.iter().map(|d| d.endpoint).collect();
    let escrows: Vec<Address> = layerzero_deployments.iter().map(|d| d.escrow).collect();
    let settlers: Vec<Address> = layerzero_deployments.iter().map(|d| d.settler).collect();

    // Verify all settler addresses are the same
    if !settlers.windows(2).all(|w| w[0] == w[1]) {
        return Err(eyre::eyre!(
            "Settler addresses are not consistent across chains: {:?}",
            settlers
        ));
    }

    // Create endpoint ID and address mappings for relay config
    let mut endpoint_addresses = alloy::primitives::map::HashMap::default();

    for (i, deployment) in layerzero_deployments.iter().enumerate() {
        let chain_id = chain_ids[i];
        endpoint_addresses.insert(chain_id, deployment.endpoint);
    }

    let relay_config = relay::config::LayerZeroConfig {
        endpoint_addresses,
        settler_signer_key: Some(LAYERZERO_DEPLOYER_PRIVATE_KEY.to_string()),
    };

    let test_config = LayerZeroTestConfig { endpoints, escrows, eids };

    Ok(LayerZeroInfrastructureDeployment { relay_config, test_config, settlers })
}
