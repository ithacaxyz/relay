//! Relay end-to-end test constants

use super::*;
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
    config::{RelayConfig, TransactionServiceConfig},
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
    sync::Arc,
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
    /// The default block number to use for forking.
    ///
    /// Negative value represents `latest - num`.
    pub fork_block_number: Option<i64>,
    pub fee_recipient: Address,
    /// Number of chains to spawn. Defaults to 1.
    pub num_chains: usize,
}

impl Default for EnvironmentConfig {
    fn default() -> Self {
        Self {
            block_time: None,
            transaction_service_config: TransactionServiceConfig {
                num_signers: 1,
                ..Default::default()
            },
            fork_block_number: None,
            fee_recipient: Address::ZERO,
            num_chains: 1,
        }
    }
}

pub struct Environment {
    /// All anvil instances
    pub anvils: Vec<AnvilInstance>,
    /// Providers for each chain
    pub providers: Vec<DynProvider>,
    /// Chain IDs for each chain (populated during setup)
    pub chain_ids: Vec<u64>,
    pub eoa: DynSigner,
    pub orchestrator: Address,
    pub delegation: Address,
    /// Minted to the eoa.
    pub fee_token: Address,
    /// Minted to the eoa.
    pub erc20: Address,
    /// Bunch of deployed erc20 which have not been minted to the eoa.
    pub erc20s: Vec<Address>,
    /// Usable ERC721 contract.
    pub erc721: Address,
    pub relay_endpoint: HttpClient,
    pub relay_handle: RelayHandle,
    pub signers: Vec<DynSigner>,
}

impl std::fmt::Debug for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Environment")
            .field("is_prep", &self.eoa.address())
            .field("eoa", &self.eoa.address())
            .field("orchestrator", &self.orchestrator)
            .field("delegation", &self.delegation)
            .field("erc20", &self.erc20)
            .field("num_chains", &self.anvils.len())
            .field("chain_ids", &self.chain_ids)
            .field("relay_endpoint", &self.relay_endpoint)
            .finish()
    }
}

/// Set up anvil instances based on configuration
async fn setup_anvil_instances(
    config: &EnvironmentConfig,
) -> eyre::Result<(Vec<AnvilInstance>, Vec<Url>)> {
    let mut anvils = Vec::with_capacity(config.num_chains);
    let mut endpoints = Vec::with_capacity(config.num_chains);

    // Spawn anvil instances
    if let Ok(endpoint) = std::env::var("TEST_EXTERNAL_ANVIL") {
        if config.block_time.is_some() {
            eyre::bail!("Cannot specify both block time and external anvil node");
        }
        endpoints
            .push(Url::from_str(&endpoint).wrap_err("Invalid endpoint on $TEST_EXTERNAL_ANVIL ")?);
        // No anvil instance for external
    } else {
        // Spawn N anvil instances
        for i in 0..config.num_chains {
            let mut args = vec![];
            let chain_id = 31337 + i as u64;

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

            let anvil = Anvil::new()
                .chain_id(chain_id)
                .args(["--optimism", "--host", "0.0.0.0"].into_iter().chain(args.into_iter()))
                .try_spawn()
                .wrap_err(format!("Failed to spawn Anvil for chain {chain_id} (index {i})"))?;

            endpoints.push(anvil.endpoint_url());
            anvils.push(anvil);
        }
    }

    Ok((anvils, endpoints))
}

/// Contract addresses for deployed contracts
#[derive(Debug, Clone)]
struct ContractAddresses {
    simulator: Address,
    delegation: Address,
    orchestrator: Address,
    erc20s: Vec<Address>,
    erc721: Address,
}

/// Set up the primary chain with contract deployments
async fn setup_primary_chain<P: Provider + WalletProvider>(
    provider: &P,
    signers: &[DynSigner],
    eoa: &DynSigner,
) -> eyre::Result<ContractAddresses> {
    // fund relay signers on first chain
    try_join_all(
        signers
            .iter()
            .map(|signer| provider.anvil_set_balance(signer.address(), U256::from(1000e18))),
    )
    .await?;

    // Deploy contracts on first chain
    let (simulator, delegation, orchestrator, erc20s, erc721) =
        get_or_deploy_contracts(provider).await?;

    // Fund EOA and mint tokens on first chain
    mint_erc20s(&erc20s[..2], &[eoa.address()], provider).await?;
    provider
        .send_transaction(TransactionRequest {
            to: Some(TxKind::Call(eoa.address())),
            value: Some(U256::from(1000e18)),
            ..Default::default()
        })
        .await?
        .get_receipt()
        .await?;

    Ok(ContractAddresses { simulator, delegation, orchestrator, erc20s, erc721 })
}

type ContractCodeTuple = (Arc<Bytes>, Arc<Bytes>, Arc<Bytes>, Arc<Bytes>, Arc<Bytes>);

/// Set up a secondary chain by replicating contracts from primary chain
async fn setup_secondary_chain<P: Provider + WalletProvider + 'static>(
    provider: P,
    contracts: &ContractAddresses,
    signers: &[DynSigner],
    eoa_address: Address,
    contract_codes: &ContractCodeTuple,
) -> eyre::Result<DynProvider> {
    let (orchestrator_code, delegation_code, simulator_code, erc721_code, erc20_code) =
        contract_codes;

    // Fund signers
    try_join_all(
        signers
            .iter()
            .map(|signer| provider.anvil_set_balance(signer.address(), U256::from(1000e18))),
    )
    .await?;

    // Set all contract codes on the current chain
    let contract_deployments = vec![
        provider.anvil_set_code(contracts.orchestrator, (**orchestrator_code).clone()),
        provider.anvil_set_code(contracts.delegation, (**delegation_code).clone()),
        provider.anvil_set_code(contracts.simulator, (**simulator_code).clone()),
        provider.anvil_set_code(contracts.erc721, (**erc721_code).clone()),
    ];

    let erc20_deployments = contracts
        .erc20s
        .iter()
        .map(|&erc20| provider.anvil_set_code(erc20, (**erc20_code).clone()));

    try_join_all(contract_deployments.into_iter().chain(erc20_deployments)).await?;

    // Fund EOA and mint tokens
    mint_erc20s(&contracts.erc20s[..2], &[eoa_address], &provider).await?;
    provider
        .send_transaction(TransactionRequest {
            to: Some(TxKind::Call(eoa_address)),
            value: Some(U256::from(1000e18)),
            ..Default::default()
        })
        .await?
        .get_receipt()
        .await?;

    Ok(provider.erased())
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

        // Multi-chain is not supported with external anvil
        if config.num_chains > 1 && std::env::var("TEST_EXTERNAL_ANVIL").is_ok() {
            eyre::bail!("Multi-chain setup is not supported with external anvil");
        }

        // Set up anvil instances
        let (anvils, endpoints) = setup_anvil_instances(&config).await?;
        let mut providers = Vec::with_capacity(config.num_chains);

        // Load signers.
        let deployer = DynSigner::from_signing_key(
            "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
        )
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

        let contracts = setup_primary_chain(&first_provider, &signers, &eoa).await?;

        // Get the code from the first chain before moving the provider
        let (orchestrator_code, delegation_code, simulator_code, erc721_code, erc20_code) = tokio::try_join!(
            first_provider.get_code_at(contracts.orchestrator),
            first_provider.get_code_at(contracts.delegation),
            first_provider.get_code_at(contracts.simulator),
            first_provider.get_code_at(contracts.erc721),
            first_provider.get_code_at(contracts.erc20s[0]) // All ERC20s have the same bytecode
        )?;

        // Wrap in Arc to avoid cloning large bytecode across chains
        let orchestrator_code = Arc::new(orchestrator_code);
        let delegation_code = Arc::new(delegation_code);
        let simulator_code = Arc::new(simulator_code);
        let erc721_code = Arc::new(erc721_code);
        let erc20_code = Arc::new(erc20_code);

        providers.push(first_provider.erased());

        // Set up remaining chains with same contract addresses
        if config.num_chains > 1 {
            let contract_codes = (
                orchestrator_code.clone(),
                delegation_code.clone(),
                simulator_code.clone(),
                erc721_code.clone(),
                erc20_code.clone(),
            );

            let setup_futures = (1..config.num_chains).map(|i| {
                let endpoint = endpoints[i].clone();
                let deployer = deployer.clone();
                let eoa_address = eoa.address();
                let contracts = contracts.clone();
                let signers = signers.clone();
                let contract_codes = contract_codes.clone();

                async move {
                    let client = ClientBuilder::default()
                        .layer(RETRY_LAYER.clone())
                        .connect(endpoint.as_str())
                        .await
                        .wrap_err(format!("Failed to connect to endpoint for chain index {i}"))?;
                    let provider = ProviderBuilder::new()
                        .wallet(EthereumWallet::from(deployer.0.clone()))
                        .connect_client(client);

                    setup_secondary_chain(
                        provider,
                        &contracts,
                        &signers,
                        eoa_address,
                        &contract_codes,
                    )
                    .await
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
                contracts.erc20s.iter().map(|erc20| ((chain_id, Some(*erc20)), CoinKind::USDT)),
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
                .with_quote_constant_rate(1.0)
                .with_fee_tokens(&[contracts.erc20s.as_slice(), &[Address::ZERO]].concat())
                .with_fee_recipient(config.fee_recipient)
                .with_orchestrator(Some(contracts.orchestrator))
                .with_delegation_proxy(Some(contracts.delegation))
                .with_simulator(Some(contracts.simulator))
                .with_intent_gas_buffer(0) // todo: temp
                .with_tx_gas_buffer(75_000) // todo: temp
                .with_transaction_service_config(config.transaction_service_config)
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
            erc20: contracts.erc20s[0],
            erc20s: contracts.erc20s[2..].to_vec(),
            erc721: contracts.erc721,
            relay_endpoint,
            relay_handle,
            signers,
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
        let signer = if !self.anvils.is_empty() {
            PrivateKeySigner::from_signing_key(self.anvils[chain_index].keys()[0].clone().into())
        } else {
            // Fallback to a default key if no anvil instances
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

/// Gets the necessary contract addresses. If they do not exist, it returns the mocked ones.
async fn get_or_deploy_contracts<P: Provider + WalletProvider>(
    provider: &P,
) -> Result<(Address, Address, Address, Vec<Address>, Address), eyre::Error> {
    let contracts_path = PathBuf::from(
        std::env::var("TEST_CONTRACTS").unwrap_or_else(|_| "tests/account/out".to_string()),
    );

    let mut orchestrator = deploy_contract(
        &provider,
        &contracts_path.join("Orchestrator.sol/Orchestrator.json"),
        Some(provider.default_signer_address().abi_encode().into()),
    )
    .await?;

    let delegation = deploy_contract(
        &provider,
        &contracts_path.join("IthacaAccount.sol/IthacaAccount.json"),
        Some(orchestrator.abi_encode().into()),
    )
    .await?;

    let mut delegation_proxy = deploy_contract(
        &provider,
        &contracts_path.join("EIP7702Proxy.sol/EIP7702Proxy.json"),
        Some((delegation, Address::ZERO).abi_encode().into()),
    )
    .await?;

    let mut simulator =
        deploy_contract(&provider, &contracts_path.join("Simulator.sol/Simulator.json"), None)
            .await?;

    // Orchestrator
    if let Ok(address) = std::env::var("TEST_ORCHESTRATOR") {
        orchestrator =
            Address::from_str(&address).wrap_err("Orchestrator address parse failed.")?;
    }

    // Proxy
    if let Ok(address) = std::env::var("TEST_PROXY") {
        delegation_proxy = Address::from_str(&address).wrap_err("Proxy address parse failed.")?
    }

    // Simulator
    if let Ok(address) = std::env::var("TEST_SIMULATOR") {
        simulator = Address::from_str(&address).wrap_err("Simulator address parse failed.")?
    }

    // Have at least 2 erc20 deployed
    let mut erc20s = Vec::with_capacity(10);
    if let Ok(orchestrator) = std::env::var("TEST_ERC20") {
        erc20s.push(Address::from_str(&orchestrator).wrap_err("ERC20 address parse failed.")?)
    };

    while erc20s.len() != 10 {
        let erc20 = deploy_contract(
            &provider,
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
        .await?;

        erc20s.push(erc20)
    }

    let erc721 = if let Ok(address) = std::env::var("TEST_ERC721") {
        Address::from_str(&address).wrap_err("ERC721 address parse failed.")?
    } else {
        deploy_contract(&provider, &contracts_path.join("MockERC721.sol/MockERC721.json"), None)
            .await?
    };

    if provider.get_code_at(MULTICALL3_ADDRESS).await?.is_empty() {
        provider.anvil_set_code(MULTICALL3_ADDRESS, MULTICALL3_BYTECODE).await?;
    }

    Ok((simulator, delegation_proxy, orchestrator, erc20s, erc721))
}

async fn deploy_contract<P: Provider>(
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
