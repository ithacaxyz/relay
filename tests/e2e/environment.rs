//! Relay end-to-end test constants

use super::*;
use crate::e2e::layerzero::LayerZeroConfig;
use alloy::{
    consensus::{SignableTransaction, TxEip1559, TxEnvelope},
    eips::Encodable2718,
    hex,
    network::{EthereumWallet, TxSignerSync},
    node_bindings::{Anvil, AnvilInstance},
    primitives::{Address, Bytes, TxKind, U256, bytes},
    providers::{
        DynProvider, MULTICALL3_ADDRESS, Provider, ProviderBuilder, WalletProvider, ext::AnvilApi,
    },
    rpc::{client::ClientBuilder, types::TransactionRequest},
    signers::local::PrivateKeySigner,
    sol_types::{SolConstructor, SolValue},
};
use eyre::{self, ContextCompat, WrapErr};
use futures_util::future::{join_all, try_join_all};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use relay::{
    config::{InteropConfig, RebalanceServiceConfig, RelayConfig, TransactionServiceConfig},
    signers::DynSigner,
    spawn::{RETRY_LAYER, RelayHandle, try_spawn},
    types::{
        CoinKind, CoinRegistry,
        rpc::{AuthorizeKeyResponse, GetKeysParameters},
    },
};
use sqlx::{ConnectOptions, Executor, PgPool, postgres::PgConnectOptions};
use std::{
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};
use url::Url;

/// Bytecode of the Multicall3 contract.
///
/// We depend on multicall contract to be present for wallet_verifySignature to work. It is
/// predeployed on most of the chains and is present on OP stack by default. However, we still need
/// to manually deploy it when working with local Anvil instance.
const MULTICALL3_BYTECODE: Bytes = bytes!(
    "0x6080604052600436106100f35760003560e01c80634d2301cc1161008a578063a8b0574e11610059578063a8b0574e1461025a578063bce38bd714610275578063c3077fa914610288578063ee82ac5e1461029b57600080fd5b80634d2301cc146101ec57806372425d9d1461022157806382ad56cb1461023457806386d516e81461024757600080fd5b80633408e470116100c65780633408e47014610191578063399542e9146101a45780633e64a696146101c657806342cbb15c146101d957600080fd5b80630f28c97d146100f8578063174dea711461011a578063252dba421461013a57806327e86d6e1461015b575b600080fd5b34801561010457600080fd5b50425b6040519081526020015b60405180910390f35b61012d610128366004610a85565b6102ba565b6040516101119190610bbe565b61014d610148366004610a85565b6104ef565b604051610111929190610bd8565b34801561016757600080fd5b50437fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0140610107565b34801561019d57600080fd5b5046610107565b6101b76101b2366004610c60565b610690565b60405161011193929190610cba565b3480156101d257600080fd5b5048610107565b3480156101e557600080fd5b5043610107565b3480156101f857600080fd5b50610107610207366004610ce2565b73ffffffffffffffffffffffffffffffffffffffff163190565b34801561022d57600080fd5b5044610107565b61012d610242366004610a85565b6106ab565b34801561025357600080fd5b5045610107565b34801561026657600080fd5b50604051418152602001610111565b61012d610283366004610c60565b61085a565b6101b7610296366004610a85565b610a1a565b3480156102a757600080fd5b506101076102b6366004610d18565b4090565b60606000828067ffffffffffffffff8111156102d8576102d8610d31565b60405190808252806020026020018201604052801561031e57816020015b6040805180820190915260008152606060208201528152602001906001900390816102f65790505b5092503660005b8281101561047757600085828151811061034157610341610d60565b6020026020010151905087878381811061035d5761035d610d60565b905060200281019061036f9190610d8f565b6040810135958601959093506103886020850185610ce2565b73ffffffffffffffffffffffffffffffffffffffff16816103ac6060870187610dcd565b6040516103ba929190610e32565b60006040518083038185875af1925050503d80600081146103f7576040519150601f19603f3d011682016040523d82523d6000602084013e6103fc565b606091505b50602080850191909152901515808452908501351761046d577f08c379a000000000000000000000000000000000000000000000000000000000600052602060045260176024527f4d756c746963616c6c333a2063616c6c206661696c656400000000000000000060445260846000fd5b5050600101610325565b508234146104e6576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601a60248201527f4d756c746963616c6c333a2076616c7565206d69736d6174636800000000000060448201526064015b60405180910390fd5b50505092915050565b436060828067ffffffffffffffff81111561050c5761050c610d31565b60405190808252806020026020018201604052801561053f57816020015b606081526020019060019003908161052a5790505b5091503660005b8281101561068657600087878381811061056257610562610d60565b90506020028101906105749190610e42565b92506105836020840184610ce2565b73ffffffffffffffffffffffffffffffffffffffff166105a66020850185610dcd565b6040516105b4929190610e32565b6000604051808303816000865af19150503d80600081146105f1576040519150601f19603f3d011682016040523d82523d6000602084013e6105f6565b606091505b5086848151811061060957610609610d60565b602090810291909101015290508061067d576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601760248201527f4d756c746963616c6c333a2063616c6c206661696c656400000000000000000060448201526064016104dd565b50600101610546565b5050509250929050565b43804060606106a086868661085a565b905093509350939050565b6060818067ffffffffffffffff8111156106c7576106c7610d31565b60405190808252806020026020018201604052801561070d57816020015b6040805180820190915260008152606060208201528152602001906001900390816106e55790505b5091503660005b828110156104e657600084828151811061073057610730610d60565b6020026020010151905086868381811061074c5761074c610d60565b905060200281019061075e9190610e76565b925061076d6020840184610ce2565b73ffffffffffffffffffffffffffffffffffffffff166107906040850185610dcd565b60405161079e929190610e32565b6000604051808303816000865af19150503d80600081146107db576040519150601f19603f3d011682016040523d82523d6000602084013e6107e0565b606091505b506020808401919091529015158083529084013517610851577f08c379a000000000000000000000000000000000000000000000000000000000600052602060045260176024527f4d756c746963616c6c333a2063616c6c206661696c656400000000000000000060445260646000fd5b50600101610714565b6060818067ffffffffffffffff81111561087657610876610d31565b6040519080825280602002602001820160405280156108bc57816020015b6040805180820190915260008152606060208201528152602001906001900390816108945790505b5091503660005b82811015610a105760008482815181106108df576108df610d60565b602002602001015190508686838181106108fb576108fb610d60565b905060200281019061090d9190610e42565b925061091c6020840184610ce2565b73ffffffffffffffffffffffffffffffffffffffff1661093f6020850185610dcd565b60405161094d929190610e32565b6000604051808303816000865af19150503d806000811461098a576040519150601f19603f3d011682016040523d82523d6000602084013e61098f565b606091505b506020830152151581528715610a07578051610a07576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601760248201527f4d756c746963616c6c333a2063616c6c206661696c656400000000000000000060448201526064016104dd565b506001016108c3565b5050509392505050565b6000806060610a2b60018686610690565b919790965090945092505050565b60008083601f840112610a4b57600080fd5b50813567ffffffffffffffff811115610a6357600080fd5b6020830191508360208260051b8501011115610a7e57600080fd5b9250929050565b60008060208385031215610a9857600080fd5b823567ffffffffffffffff811115610aaf57600080fd5b610abb85828601610a39565b90969095509350505050565b6000815180845260005b81811015610aed57602081850181015186830182015201610ad1565b81811115610aff576000602083870101525b50601f017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0169290920160200192915050565b600082825180855260208086019550808260051b84010181860160005b84811015610bb1578583037fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe001895281518051151584528401516040858501819052610b9d81860183610ac7565b9a86019a9450505090830190600101610b4f565b5090979650505050505050565b602081526000610bd16020830184610b32565b9392505050565b600060408201848352602060408185015281855180845260608601915060608160051b870101935082870160005b82811015610c52577fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa0888703018452610c40868351610ac7565b95509284019290840190600101610c06565b509398975050505050505050565b600080600060408486031215610c7557600080fd5b83358015158114610c8557600080fd5b9250602084013567ffffffffffffffff811115610ca157600080fd5b610cad86828701610a39565b9497909650939450505050565b838152826020820152606060408201526000610cd96060830184610b32565b95945050505050565b600060208284031215610cf457600080fd5b813573ffffffffffffffffffffffffffffffffffffffff81168114610bd157600080fd5b600060208284031215610d2a57600080fd5b5035919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b600082357fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff81833603018112610dc357600080fd5b9190910192915050565b60008083357fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe1843603018112610e0257600080fd5b83018035915067ffffffffffffffff821115610e1d57600080fd5b602001915036819003821315610a7e57600080fd5b8183823760009101908152919050565b600082357fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc1833603018112610dc357600080fd5b600082357fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa1833603018112610dc357600080fdfea2646970667358221220bb2b5c71a328032f97c676ae39a1ec2148d3e5d6f73d95e9b17910152d61f16264736f6c634300080c0033"
);

/// All settings for configuring the [`Environment`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct EnvironmentConfig {
    pub block_time: Option<f64>,
    pub transaction_service_config: TransactionServiceConfig,
    pub rebalance_service_config: Option<RebalanceServiceConfig>,
    /// The default block number to use for forking.
    ///
    /// Negative value represents `latest - num`.
    pub fork_block_number: Option<i64>,
    pub fee_recipient: Address,
    /// Number of chains to spawn. Defaults to 1.
    pub num_chains: usize,
    /// Interop configuration.
    pub interop_config: InteropConfig,
}

impl Default for EnvironmentConfig {
    fn default() -> Self {
        Self {
            block_time: None,
            transaction_service_config: TransactionServiceConfig {
                num_signers: 1,
                ..Default::default()
            },
            rebalance_service_config: None,
            fork_block_number: None,
            fee_recipient: Address::ZERO,
            num_chains: 1,
            interop_config: InteropConfig {
                refund_check_interval: Duration::from_millis(100),
                escrow_refund_threshold: 60,
            },
        }
    }
}

pub struct Environment {
    /// All anvil instances (None for external anvil)
    pub anvils: Vec<Option<AnvilInstance>>,
    /// Providers for each chain
    pub providers: Vec<DynProvider>,
    /// Chain IDs for each chain (populated during setup)
    pub chain_ids: Vec<u64>,
    pub eoa: DynSigner,
    pub orchestrator: Address,
    pub delegation: Address,
    pub funder: Address,
    /// Minted to the eoa.
    pub fee_token: Address,
    /// Minted to the eoa.
    pub erc20: Address,
    /// Bunch of deployed erc20 which have not been minted to the eoa.
    pub erc20s: Vec<Address>,
    /// Usable ERC721 contract.
    pub erc721: Address,
    /// Escrow contract for cross-chain intents.
    pub escrow: Address,
    /// Settler contract for cross-chain settlement.
    pub settler: Address,
    pub relay_endpoint: HttpClient,
    pub relay_handle: RelayHandle,
    pub signers: Vec<DynSigner>,
    /// Settlement configuration for cross-chain messaging
    pub settlement: SettlementConfig,
    pub deployer: DynSigner,
}

impl std::fmt::Debug for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Environment")
            .field("is_prep", &self.eoa.address())
            .field("eoa", &self.eoa.address())
            .field("orchestrator", &self.orchestrator)
            .field("delegation", &self.delegation)
            .field("erc20", &self.erc20)
            .field("escrow", &self.escrow)
            .field("settler", &self.settler)
            .field("num_chains", &self.anvils.len())
            .field("chain_ids", &self.chain_ids)
            .field("relay_endpoint", &self.relay_endpoint)
            .finish()
    }
}

/// Settlement configuration for cross-chain messaging
#[derive(Debug, Clone, Default)]
pub struct SettlementConfig {
    /// LayerZero configuration
    pub layerzero: Option<LayerZeroConfig>,
}

/// Set up anvil instances based on configuration
async fn setup_anvil_instances(
    config: &EnvironmentConfig,
) -> eyre::Result<(Vec<Option<AnvilInstance>>, Vec<Url>)> {
    let mut anvils = Vec::with_capacity(config.num_chains);
    let mut endpoints = Vec::with_capacity(config.num_chains);

    let external_endpoint = std::env::var("TEST_EXTERNAL_ANVIL").ok();

    if let Some(endpoint) = &external_endpoint {
        if config.block_time.is_some() {
            eyre::bail!("Cannot specify both block time and external anvil node");
        }

        if config.num_chains == 1 {
            // Single chain mode - only use external
            endpoints.push(
                Url::from_str(endpoint).wrap_err("Invalid endpoint on $TEST_EXTERNAL_ANVIL")?,
            );
            // Add None to anvils to maintain count
            anvils.push(None);
        } else {
            // Multi-chain mode - external as first, then spawn n-1 local anvils
            // Add external as first endpoint
            endpoints.push(
                Url::from_str(endpoint).wrap_err("Invalid endpoint on $TEST_EXTERNAL_ANVIL")?,
            );
            // Add None to maintain anvils.len() == num_chains
            anvils.push(None);

            // Spawn n-1 local anvils after the external one
            for i in 1..config.num_chains {
                let anvil = spawn_local_anvil(i, config)?;
                endpoints.push(anvil.endpoint_url());
                anvils.push(Some(anvil));
            }
        }
    } else {
        // No external anvil - spawn all local instances
        for i in 0..config.num_chains {
            let anvil = spawn_local_anvil(i, config)?;
            endpoints.push(anvil.endpoint_url());
            anvils.push(Some(anvil));
        }
    }

    Ok((anvils, endpoints))
}

/// Helper function to spawn a local anvil instance
fn spawn_local_anvil(index: usize, config: &EnvironmentConfig) -> eyre::Result<AnvilInstance> {
    let mut args = vec![];
    let chain_id = 31337 + index as u64;

    // fork off a block a few blocks lower than `latest` by default
    let fork_block_number = config.fork_block_number.unwrap_or(-3).to_string();
    let fork_url = std::env::var("TEST_FORK_URL");
    if let Ok(fork_url) = &fork_url {
        args.extend(["--fork-url", fork_url]);
        args.extend(["--fork-block-number", &fork_block_number]);
    }
    let block_time = config.block_time.map(|t| t.to_string());
    if let Some(block_time) = &block_time {
        args.extend(["--block-time", block_time]);
    }

    let fork_block_number = std::env::var("TEST_FORK_BLOCK_NUMBER");
    if let Ok(fork_block_number) = &fork_block_number {
        args.extend(["--fork-block-number", fork_block_number]);
    }

    Anvil::new()
        .chain_id(chain_id)
        .args(["--optimism", "--host", "0.0.0.0"].into_iter().chain(args))
        .try_spawn()
        .wrap_err(format!("Failed to spawn Anvil for chain {chain_id} (index {index})"))
}

/// Contract addresses for deployed contracts
#[derive(Clone)]
struct ContractAddresses {
    simulator: Address,
    delegation: Address,
    #[allow(dead_code)]
    delegation_implementation: Address,
    orchestrator: Address,
    funder: Address,
    escrow: Address,
    settler: Address,
    erc20s: Vec<Address>,
    erc721: Address,
}

/// Fund signers with ETH
async fn fund_signers<P: Provider>(provider: &P, signers: &[DynSigner]) -> eyre::Result<()> {
    try_join_all(
        signers
            .iter()
            .map(|signer| provider.anvil_set_balance(signer.address(), U256::from(1000e18))),
    )
    .await?;
    Ok(())
}

/// Set up chain state after contracts are deployed
async fn setup_chain_with_contracts<P: Provider>(
    provider: &P,
    contracts: &ContractAddresses,
    signers: &[DynSigner],
    eoa_address: Address,
) -> eyre::Result<()> {
    // Fund funder contract
    provider.anvil_set_balance(contracts.funder, U256::from(1000e18)).await?;

    // Fund EOA and mint tokens
    let holders = &[eoa_address, contracts.funder]
        .iter()
        .copied()
        .chain(signers.iter().map(|s| s.address()))
        .collect::<Vec<_>>();

    mint_erc20s(&contracts.erc20s[..2], holders, provider).await?;

    // Fund EOA with ETH
    provider
        .send_transaction(TransactionRequest {
            to: Some(TxKind::Call(eoa_address)),
            value: Some(U256::from(1000e18)),
            ..Default::default()
        })
        .await?
        .get_receipt()
        .await?;

    Ok(())
}

/// Set up a chain with all contracts and initial state
async fn setup_chain<P: Provider + WalletProvider>(
    provider: &P,
    signers: &[DynSigner],
    eoa_address: Address,
    is_primary: bool,
) -> eyre::Result<ContractAddresses> {
    // Fund signers
    fund_signers(provider, signers).await?;

    // Deploy all contracts - this will result in the same addresses across all chains
    // because we use the same deployer account and nonce sequence
    let contracts = deploy_all_contracts(provider).await?;

    // Set up chain with deployed contracts
    setup_chain_with_contracts(provider, &contracts, signers, eoa_address).await?;

    // Additional minting for funder on secondary chains
    if !is_primary {
        for _ in 0..5 {
            mint_erc20s(&contracts.erc20s[..2], &[contracts.funder], provider).await?;
        }
    }

    Ok(contracts)
}

impl Environment {
    /// Sets up the test environment with a upgraded account using [`DynSigner`].
    ///
    /// Read [`Self::setup`] for more information on setup.
    pub async fn setup() -> eyre::Result<Self> {
        Self::setup_with_config(EnvironmentConfig::default()).await
    }

    /// Sets up a multi-chain test environment with N chains.
    pub async fn setup_multi_chain(num_chains: usize) -> eyre::Result<Self> {
        Self::setup_with_config(EnvironmentConfig { num_chains, ..Default::default() }).await
    }

    /// Sets up the test environment including Anvil, contracts, and the relay service.
    ///
    /// Available environment variables:
    /// - `TEST_EXTERNAL_ANVIL`: Use an external node instead of spawning Anvil.
    /// - `TEST_FORK_URL` / `TEST_FORK_BLOCK_NUMBER`: Fork settings for inprocess spawned Anvil.
    /// - `TEST_EOA_PRIVATE_KEY`: Private key for the EOA signer (defaults to `EOA_PRIVATE_KEY`).
    /// - `TEST_CONTRACTS`: Directory for contract artifacts (defaults to `tests/account/out`).
    /// - `TEST_ORCHESTRATOR`: Address for Orchestrator contract; deploys a mock if unset.
    /// - `TEST_PROXY`: Address for Proxy contract; deploys a mock if unset.
    /// - `TEST_ERC20`: Address for ERC20 token; deploys a mock if unset.
    /// - `TEST_ERC721`: Address for the ERC721 token; deploys a mock if unset.
    ///
    /// Example `.env`:
    /// ```env
    /// TEST_EXTERNAL_ANVIL="http://localhost:8545"
    /// TEST_FORK_URL="https://odyssey.ithaca.xyz"
    /// TEST_FORK_BLOCK_NUMBER=11577300
    /// TEST_EOA_PRIVATE_KEY=0xabc123...
    /// TEST_CONTRACTS="./tests/account/out"
    /// TEST_ORCHESTRATOR="0xOrchestratorAddress"
    /// TEST_PROXY="0xProxyAddress"
    /// TEST_ERC20="0xYourErc20Address"
    /// TEST_ERC721="0xYourErc721Address"
    /// ```
    pub async fn setup_with_config(config: EnvironmentConfig) -> eyre::Result<Self> {
        dotenvy::dotenv().ok();

        // Early validation
        if config.num_chains == 0 {
            eyre::bail!("Number of chains must be greater than 0");
        }

        // Set up anvil instances
        let (anvils, endpoints) = setup_anvil_instances(&config).await?;
        let mut providers = Vec::with_capacity(config.num_chains);

        // Load signers.
        let deployer = DynSigner::from_signing_key(&DEPLOYER_PRIVATE_KEY.to_string())
            .await
            .wrap_err("Relay signer load failed")?;

        let signers = DynSigner::derive_from_mnemonic(
            SIGNERS_MNEMONIC.parse()?,
            config.transaction_service_config.num_signers,
        )?;

        let eoa = DynSigner::from_signing_key(
            &std::env::var("TEST_EOA_PRIVATE_KEY").unwrap_or(EOA_PRIVATE_KEY.to_string()),
        )
        .await
        .wrap_err("EOA signer load failed")?;

        // Set up primary chain with contract deployments
        let client = ClientBuilder::default()
            .layer(RETRY_LAYER.clone())
            .connect(endpoints[0].as_str())
            .await?;
        let first_provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(deployer.0.clone()))
            .connect_client(client);

        let contracts = setup_chain(&first_provider, &signers, eoa.address(), true).await?;

        providers.push(first_provider.erased());

        // Set up remaining chains with same contract addresses
        if config.num_chains > 1 {
            let setup_futures = (1..config.num_chains).map(|i| {
                let endpoint = endpoints[i].clone();
                let deployer = deployer.clone();
                let eoa_address = eoa.address();
                let signers = signers.clone();

                async move {
                    let client = ClientBuilder::default()
                        .layer(RETRY_LAYER.clone())
                        .connect(endpoint.as_str())
                        .await
                        .wrap_err(format!("Failed to connect to endpoint for chain index {i}"))?;
                    let provider = ProviderBuilder::new()
                        .wallet(EthereumWallet::from(deployer.0.clone()))
                        .connect_client(client);

                    setup_chain(&provider, &signers, eoa_address, false).await?;
                    Ok::<DynProvider, eyre::Error>(provider.erased())
                }
            });

            let additional_providers = try_join_all(setup_futures).await?;
            providers.extend(additional_providers);
        }

        // Query chain IDs from all providers
        let chain_ids =
            try_join_all(providers.iter().map(|provider| provider.get_chain_id())).await?;

        // Build registry with tokens from all chains
        let mut registry = CoinRegistry::default();
        for &chain_id in &chain_ids {
            registry.extend(
                contracts
                    .erc20s
                    .iter()
                    .map(|contract| ((chain_id, Some(*contract)), CoinKind::USDT)),
            );
        }

        let database_url = if let Ok(db_url) = std::env::var("DATABASE_URL") {
            let opts = PgConnectOptions::from_str(&db_url)?;
            let pool = PgPool::connect_with(opts.clone()).await?;

            // create a separate database for this test and override database name in the url
            let database_name = format!("relay_test_database_{}", rand::random::<u64>());
            pool.execute(format!("create database {database_name}").as_str()).await?;

            Some(opts.database(&database_name).to_url_lossy().to_string())
        } else {
            None
        };

        // Start relay service with all endpoints
        let relay_handle = try_spawn(
            RelayConfig::default()
                .with_port(0)
                .with_metrics_port(0)
                .with_endpoints(&endpoints)
                .with_quote_ttl(Duration::from_secs(60))
                .with_rate_ttl(Duration::from_secs(300))
                .with_signers_mnemonic(SIGNERS_MNEMONIC.parse().unwrap())
                .with_funder_key(DEPLOYER_PRIVATE_KEY.to_string())
                .with_quote_constant_rate(Some(1.0))
                .with_fee_tokens(&[contracts.erc20s.clone(), vec![Address::ZERO]].concat())
                .with_interop_tokens(&[contracts.erc20s[0]])
                .with_fee_recipient(config.fee_recipient)
                .with_orchestrator(Some(contracts.orchestrator))
                .with_delegation_proxy(Some(contracts.delegation))
                .with_simulator(Some(contracts.simulator))
                .with_funder(Some(contracts.funder))
                .with_escrow(Some(contracts.escrow))
                .with_settler(Some(contracts.settler))
                .with_intent_gas_buffer(20_000) // todo: temp
                .with_tx_gas_buffer(75_000) // todo: temp
                .with_transaction_service_config(config.transaction_service_config)
                .with_interop_config(config.interop_config)
                .with_rebalance_service_config(config.rebalance_service_config)
                .with_database_url(database_url),
            registry,
        )
        .await?;

        let relay_endpoint = HttpClientBuilder::default()
            .build(relay_handle.http_url())
            .wrap_err("Failed to build relay client")?;

        Ok(Self {
            anvils,
            providers,
            chain_ids,
            eoa,
            orchestrator: contracts.orchestrator,
            delegation: contracts.delegation,
            fee_token: contracts.erc20s[1],
            funder: contracts.funder,
            erc20: contracts.erc20s[0],
            erc20s: contracts.erc20s[2..].to_vec(),
            erc721: contracts.erc721,
            escrow: contracts.escrow,
            settler: contracts.settler,
            relay_endpoint,
            relay_handle,
            signers,
            settlement: SettlementConfig::default(),
            deployer,
        })
    }

    /// Sets [`Environment::fee_token`] to the native token.
    pub fn with_native_payment(mut self) -> Self {
        self.fee_token = Address::ZERO;
        self
    }

    /// Get the chain ID for a specific chain index.
    ///
    /// # Panics
    ///
    /// This method panics if the chain index is out of bounds.
    pub fn chain_id_for(&self, index: usize) -> u64 {
        self.chain_ids
            .get(index)
            .copied()
            .unwrap_or_else(|| panic!("No chain ID for chain index {index}"))
    }

    /// Get the provider for a specific chain index.
    ///
    /// # Panics
    ///
    /// This method panics if the chain index is out of bounds.
    pub fn provider_for(&self, index: usize) -> &DynProvider {
        self.providers.get(index).unwrap_or_else(|| panic!("No provider for chain index {index}"))
    }

    /// Get the default provider (first chain).
    pub fn provider_default(&self) -> &DynProvider {
        &self.providers[0]
    }

    /// Get the number of chains.
    pub fn num_chains(&self) -> usize {
        self.anvils.len()
    }

    /// Get the first chain's provider
    pub fn provider(&self) -> &DynProvider {
        &self.providers[0]
    }

    /// Get the first chain's ID
    pub fn chain_id(&self) -> u64 {
        self.chain_id_for(0)
    }

    /// Gets the on-chain EOA authorized keys for a specific chain.
    pub async fn get_eoa_authorized_keys_on_chain(
        &self,
        chain_index: usize,
    ) -> eyre::Result<Vec<AuthorizeKeyResponse>> {
        Ok(self
            .relay_endpoint
            .get_keys(GetKeysParameters {
                address: self.eoa.address(),
                chain_id: self.chain_id_for(chain_index),
            })
            .await?)
    }

    /// Gets the on-chain EOA authorized keys for the default chain.
    pub async fn get_eoa_authorized_keys(&self) -> eyre::Result<Vec<AuthorizeKeyResponse>> {
        self.get_eoa_authorized_keys_on_chain(0).await
    }

    /// Drops a transaction from the Anvil txpool and returns it on a specific chain.
    pub async fn drop_transaction_on_chain(
        &self,
        hash: B256,
        chain_index: usize,
    ) -> Option<TxEnvelope> {
        let provider = self.provider_for(chain_index);
        let tx =
            provider.get_transaction_by_hash(hash).await.unwrap().map(|tx| tx.inner.into_inner());
        provider.anvil_drop_transaction(hash).await.unwrap();
        assert!(provider.get_transaction_by_hash(hash).await.unwrap().is_none());
        tx
    }

    /// Drops a transaction from the default chain.
    pub async fn drop_transaction(&self, hash: B256) -> Option<TxEnvelope> {
        self.drop_transaction_on_chain(hash, 0).await
    }

    /// Disables mining of blocks on a specific chain.
    ///
    /// Note: anvil does not expose API to disable mining so we're firstly switching it to auto
    /// mining and then disabling it. This means that this method would cause a block mined while
    /// executed.
    pub async fn disable_mining_on_chain(&self, chain_index: usize) {
        let provider = self.provider_for(chain_index);
        provider.anvil_set_auto_mine(true).await.unwrap();
        provider.anvil_set_auto_mine(false).await.unwrap();
    }

    /// Disables mining on the default chain.
    pub async fn disable_mining(&self) {
        self.disable_mining_on_chain(0).await
    }

    /// Enables mining of blocks on a specific chain.
    pub async fn enable_mining_on_chain(&self, chain_index: usize) {
        let provider = self.provider_for(chain_index);
        provider.anvil_set_auto_mine(true).await.unwrap();
    }

    /// Enables mining on the default chain.
    pub async fn enable_mining(&self) {
        self.enable_mining_on_chain(0).await
    }

    /// Mines a single block on a specific chain.
    pub async fn mine_block_on_chain(&self, chain_index: usize) {
        let provider = self.provider_for(chain_index);
        provider.anvil_mine(None, None).await.unwrap();
    }

    /// Mines a block on the default chain.
    pub async fn mine_block(&self) {
        self.mine_block_on_chain(0).await
    }

    /// Mines 10 blocks with dummy transactions with the given priority fee on a specific chain.
    ///
    /// Can be used to inflate the priority fee market.
    pub async fn mine_blocks_with_priority_fee_on_chain(
        &self,
        priority_fee: u128,
        chain_index: usize,
    ) {
        let provider = self.provider_for(chain_index);

        let chain_id = self.chain_id_for(chain_index);

        // Use a funded account
        let signer = if let Some(anvil) = self.anvils.get(chain_index).and_then(|a| a.as_ref()) {
            PrivateKeySigner::from_signing_key(anvil.keys()[0].clone().into())
        } else {
            // Fallback to a default key for external anvil
            PrivateKeySigner::from_signing_key(
                "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
                    .parse()
                    .unwrap(),
            )
        };

        for _ in 0..10 {
            let nonce = provider.get_transaction_count(signer.address()).await.unwrap();
            let max_fee_per_gas = provider.estimate_eip1559_fees().await.unwrap().max_fee_per_gas;

            join_all((0..10).map(|i| {
                let signer = &signer;
                async move {
                    let mut tx = TxEip1559 {
                        chain_id,
                        nonce: nonce + i as u64,
                        to: Address::ZERO.into(),
                        gas_limit: 21000,
                        max_fee_per_gas: priority_fee + max_fee_per_gas,
                        max_priority_fee_per_gas: priority_fee,
                        ..Default::default()
                    };
                    let signature = (&signer).sign_transaction_sync(&mut tx).unwrap();
                    let tx = TxEnvelope::Eip1559(tx.into_signed(signature));

                    let _ = provider.send_raw_transaction(&tx.encoded_2718()).await.unwrap();
                }
            }))
            .await;

            self.mine_block_on_chain(chain_index).await;
        }
    }

    /// Mines blocks with priority fee on the default chain.
    pub async fn mine_blocks_with_priority_fee(&self, priority_fee: u128) {
        self.mine_blocks_with_priority_fee_on_chain(priority_fee, 0).await
    }

    /// Fetches the current base_fee_per_gas and spawns a task setting blocks basefee to it on a
    /// specific chain.
    pub async fn freeze_basefee_on_chain(&self, chain_index: usize) {
        let provider = self.provider_for(chain_index).clone();

        let basefee = provider
            .get_block(Default::default())
            .await
            .unwrap()
            .unwrap()
            .header
            .base_fee_per_gas
            .unwrap() as u128;

        // spawn a task setting basefee for next block to a fixed value.
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                provider.anvil_set_next_block_base_fee_per_gas(basefee).await.unwrap();
            }
        });
    }

    /// Freezes basefee on the default chain.
    pub async fn freeze_basefee(&self) {
        self.freeze_basefee_on_chain(0).await
    }

    /// Extracts RPC URLs for all chains in the environment.
    ///
    /// Returns a vector of RPC URLs in the same order as the chains are indexed.
    /// For local anvil instances, returns their endpoint URLs.
    /// For external anvil instances, returns the TEST_EXTERNAL_ANVIL environment variable value.
    pub fn get_rpc_urls(&self) -> eyre::Result<Vec<String>> {
        let mut urls = Vec::with_capacity(self.anvils.len());

        for anvil in &self.anvils {
            let url = if let Some(anvil_instance) = anvil {
                anvil_instance.endpoint_url().to_string()
            } else {
                std::env::var("TEST_EXTERNAL_ANVIL")
                    .wrap_err("TEST_EXTERNAL_ANVIL not set for external anvil")?
            };
            urls.push(url);
        }

        Ok(urls)
    }
}

/// Mint ERC20s into the addresses.
pub async fn mint_erc20s<P: Provider>(
    erc20s: &[Address],
    addresses: &[Address],
    provider: P,
) -> Result<(), eyre::Error> {
    for erc20 in erc20s {
        // Mint tokens for both signers.
        for addr in addresses {
            MockErc20::new(*erc20, &provider)
                .mint(*addr, U256::from(100e18))
                .send()
                .await
                .wrap_err("Minting failed")?
                .get_receipt()
                .await?;
        }
    }
    Ok(())
}

/// Deploy all contracts in a deterministic way
async fn deploy_all_contracts<P: Provider + WalletProvider>(
    provider: &P,
) -> Result<ContractAddresses, eyre::Error> {
    let contracts_path = PathBuf::from(
        std::env::var("TEST_CONTRACTS").unwrap_or_else(|_| "tests/account/out".to_string()),
    );

    // Deploy contracts using environment variables if provided, otherwise deploy new ones
    let orchestrator = if let Ok(address) = std::env::var("TEST_ORCHESTRATOR") {
        Address::from_str(&address).wrap_err("Orchestrator address parse failed.")?
    } else {
        deploy_orchestrator(provider, &contracts_path).await?
    };

    let funder = deploy_funder(provider, &contracts_path, orchestrator).await?;

    let (delegation_implementation, delegation_proxy) =
        if let Ok(address) = std::env::var("TEST_PROXY") {
            let delegation_implementation =
                deploy_delegation_implementation(provider, &contracts_path, orchestrator).await?;
            (
                delegation_implementation,
                Address::from_str(&address).wrap_err("Proxy address parse failed.")?,
            )
        } else {
            deploy_delegation_contracts(provider, &contracts_path, orchestrator).await?
        };

    let simulator = if let Ok(address) = std::env::var("TEST_SIMULATOR") {
        Address::from_str(&address).wrap_err("Simulator address parse failed.")?
    } else {
        deploy_simulator(provider, &contracts_path).await?
    };

    // Deploy ERC20 tokens
    let erc20s = if let Ok(address) = std::env::var("TEST_ERC20") {
        let mut erc20s = Vec::with_capacity(10);
        erc20s.push(Address::from_str(&address).wrap_err("ERC20 address parse failed.")?);
        // Deploy remaining ERC20s
        while erc20s.len() < 10 {
            erc20s.push(deploy_erc20(provider, &contracts_path).await?);
        }
        erc20s
    } else {
        deploy_erc20_tokens(provider, &contracts_path, 10).await?
    };

    let erc721 = if let Ok(address) = std::env::var("TEST_ERC721") {
        Address::from_str(&address).wrap_err("ERC721 address parse failed.")?
    } else {
        deploy_erc721(provider, &contracts_path).await?
    };

    let escrow = if let Ok(address) = std::env::var("TEST_ESCROW") {
        Address::from_str(&address).wrap_err("Escrow address parse failed.")?
    } else {
        deploy_escrow(provider, &contracts_path).await?
    };

    let settler = if let Ok(address) = std::env::var("TEST_SETTLER") {
        Address::from_str(&address).wrap_err("Settler address parse failed.")?
    } else {
        deploy_settler(provider, &contracts_path, provider.default_signer_address()).await?
    };

    // Deploy Multicall3 if needed
    if provider.get_code_at(MULTICALL3_ADDRESS).await?.is_empty() {
        provider.anvil_set_code(MULTICALL3_ADDRESS, MULTICALL3_BYTECODE).await?;
    }

    Ok(ContractAddresses {
        simulator,
        delegation: delegation_proxy,
        delegation_implementation,
        orchestrator,
        funder,
        escrow,
        settler,
        erc20s,
        erc721,
    })
}

/// Deploy the Orchestrator contract
async fn deploy_orchestrator<P: Provider + WalletProvider>(
    provider: &P,
    contracts_path: &Path,
) -> eyre::Result<Address> {
    deploy_contract(
        provider,
        &contracts_path.join("Orchestrator.sol/Orchestrator.json"),
        Some(provider.default_signer_address().abi_encode().into()),
    )
    .await
}

/// Deploy the SimpleFunder contract
async fn deploy_funder<P: Provider + WalletProvider>(
    provider: &P,
    contracts_path: &Path,
    orchestrator: Address,
) -> eyre::Result<Address> {
    let funder_eoa = provider.default_signer_address();
    deploy_contract(
        provider,
        &contracts_path.join("SimpleFunder.sol/SimpleFunder.json"),
        Some((funder_eoa, orchestrator, funder_eoa).abi_encode().into()),
    )
    .await
}

/// Deploy the delegation implementation contract
async fn deploy_delegation_implementation<P: Provider>(
    provider: &P,
    contracts_path: &Path,
    orchestrator: Address,
) -> eyre::Result<Address> {
    deploy_contract(
        provider,
        &contracts_path.join("IthacaAccount.sol/IthacaAccount.json"),
        Some(orchestrator.abi_encode().into()),
    )
    .await
}

/// Deploy both delegation contracts (implementation and proxy)
async fn deploy_delegation_contracts<P: Provider>(
    provider: &P,
    contracts_path: &Path,
    orchestrator: Address,
) -> eyre::Result<(Address, Address)> {
    let delegation =
        deploy_delegation_implementation(provider, contracts_path, orchestrator).await?;

    let delegation_proxy = deploy_contract(
        provider,
        &contracts_path.join("EIP7702Proxy.sol/EIP7702Proxy.json"),
        Some((delegation, Address::ZERO).abi_encode().into()),
    )
    .await?;

    Ok((delegation, delegation_proxy))
}

/// Deploy the Simulator contract
async fn deploy_simulator<P: Provider>(
    provider: &P,
    contracts_path: &Path,
) -> eyre::Result<Address> {
    deploy_contract(provider, &contracts_path.join("Simulator.sol/Simulator.json"), None).await
}

/// Deploy a single ERC20 token
async fn deploy_erc20<P: Provider>(provider: &P, contracts_path: &Path) -> eyre::Result<Address> {
    deploy_contract(
        provider,
        &contracts_path.join("MockERC20.sol/MockERC20.json"),
        Some(
            MockErc20::constructorCall {
                name_: "mockName".into(),
                symbol_: "mockSymbol".into(),
                decimals_: 18,
            }
            .abi_encode()
            .into(),
        ),
    )
    .await
}

/// Deploy multiple ERC20 tokens
async fn deploy_erc20_tokens<P: Provider>(
    provider: &P,
    contracts_path: &Path,
    count: usize,
) -> eyre::Result<Vec<Address>> {
    let mut erc20s = Vec::with_capacity(count);
    for _ in 0..count {
        erc20s.push(deploy_erc20(provider, contracts_path).await?);
    }
    Ok(erc20s)
}

/// Deploy an ERC721 token
async fn deploy_erc721<P: Provider>(provider: &P, contracts_path: &Path) -> eyre::Result<Address> {
    deploy_contract(provider, &contracts_path.join("MockERC721.sol/MockERC721.json"), None).await
}

/// Deploy the Escrow contract
async fn deploy_escrow<P: Provider>(provider: &P, contracts_path: &Path) -> eyre::Result<Address> {
    deploy_contract(provider, &contracts_path.join("Escrow.sol/Escrow.json"), None).await
}

/// Deploy the Settler contract
async fn deploy_settler<P: Provider>(
    provider: &P,
    contracts_path: &Path,
    owner: Address,
) -> eyre::Result<Address> {
    deploy_contract(
        provider,
        &contracts_path.join("SimpleSettler.sol/SimpleSettler.json"),
        Some(owner.abi_encode().into()),
    )
    .await
}

pub async fn deploy_contract<P: Provider>(
    provider: &P,
    artifact_path: &Path,
    args: Option<Bytes>,
) -> eyre::Result<Address> {
    let artifact_str = std::fs::read_to_string(artifact_path)
        .wrap_err_with(|| format!("Failed to read artifact at {}", artifact_path.display()))?;
    let artifact: serde_json::Value =
        serde_json::from_str(&artifact_str).wrap_err("Failed to parse artifact JSON")?;
    let bytecode = artifact
        .get("bytecode")
        .and_then(|b| b.get("object"))
        .and_then(|b| b.as_str())
        .ok_or_else(|| eyre::eyre!("No bytecode found in artifact"))?;

    let mut bytecode = hex::decode(bytecode).wrap_err_with(|| {
        format!("Failed to decode bytecode from artifact at {}", artifact_path.display())
    })?;
    bytecode.extend_from_slice(&args.unwrap_or_default());

    provider
        .send_transaction(TransactionRequest {
            input: bytecode.into(),
            to: Some(TxKind::Create),
            ..Default::default()
        })
        .await?
        .get_receipt()
        .await?
        .contract_address
        .wrap_err_with(|| format!("Failed to deploy artifact at {}", artifact_path.display()))
}
