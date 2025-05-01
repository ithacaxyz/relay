//! Relay end-to-end test constants

use super::{eoa::EoaKind, *};
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
use futures_util::future::join_all;
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
    pub is_prep: bool,
    pub block_time: Option<f64>,
    pub transaction_service_config: TransactionServiceConfig,
    /// The default block number to use for forking.
    ///
    /// Negative value represents `latest - num`.
    pub fork_block_number: Option<i64>,
}

impl Default for EnvironmentConfig {
    fn default() -> Self {
        Self {
            is_prep: false,
            block_time: None,
            transaction_service_config: TransactionServiceConfig {
                num_signers: 1,
                ..Default::default()
            },
            fork_block_number: None,
        }
    }
}

pub struct Environment {
    pub _anvil: Option<AnvilInstance>,
    pub provider: DynProvider,
    pub eoa: EoaKind,
    pub entrypoint: Address,
    pub delegation: Address,
    /// Minted to the eoa.
    pub fee_token: Address,
    /// Minted to the eoa.
    pub erc20: Address,
    /// Bunch of deployed erc20 which have not been minted to the eoa.
    pub erc20s: Vec<Address>,
    /// Usable ERC721 contract.
    pub erc721: Address,
    pub chain_id: u64,
    pub relay_endpoint: HttpClient,
    pub relay_handle: RelayHandle,
}

impl std::fmt::Debug for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Environment")
            .field("is_prep", &self.eoa.address())
            .field("eoa", &self.eoa.address())
            .field("entrypoint", &self.entrypoint)
            .field("delegation", &self.delegation)
            .field("erc20", &self.erc20)
            .field("chain_id", &self.chain_id)
            .field("relay_endpoint", &self.relay_endpoint)
            .finish()
    }
}

impl Environment {
    /// Sets up the test environment with a [`PREPAccount`].
    ///
    /// Read [`Self::setup`] for more information on setup.
    pub async fn setup_with_prep() -> eyre::Result<Self> {
        Self::setup(EnvironmentConfig { is_prep: true, ..Default::default() }).await
    }

    /// Sets up the test environment with a upgraded account using [`DynSigner`].
    ///
    /// Read [`Self::setup`] for more information on setup.
    pub async fn setup_with_upgraded() -> eyre::Result<Self> {
        Self::setup(EnvironmentConfig { is_prep: false, ..Default::default() }).await
    }

    /// Sets up the test environment including Anvil, contracts, and the relay service.
    ///
    /// Available environment variables:
    /// - `TEST_EXTERNAL_ANVIL`: Use an external node instead of spawning Anvil.
    /// - `TEST_FORK_URL` / `TEST_FORK_BLOCK_NUMBER`: Fork settings for inprocess spawned Anvil.
    /// - `TEST_EOA_PRIVATE_KEY`: Private key for the EOA signer (defaults to `EOA_PRIVATE_KEY`).
    /// - `TEST_CONTRACTS`: Directory for contract artifacts (defaults to `tests/account/out`).
    /// - `TEST_ENTRYPOINT`: Address for EntryPoint contract; deploys a mock if unset.
    /// - `TEST_DELEGATION`: Address for Delegation contract; deploys a mock if unset.
    /// - `TEST_ACCOUNT_REGISTRY`: Address for AccountRegistry contract; deploys a mock if unset.
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
    /// TEST_ENTRYPOINT="0xEntryPointAddress"
    /// TEST_DELEGATION="0xDelegationAddress"
    /// TEST_ACCOUNT_REGISTRY="0xAccountRegistryAddress"
    /// TEST_ERC20="0xYourErc20Address"
    /// TEST_ERC721="0xYourErc721Address"
    /// ```
    pub async fn setup(config: EnvironmentConfig) -> eyre::Result<Self> {
        dotenvy::dotenv().ok();

        // Spawns a local Ethereum node if one is not specified.
        let (endpoint, anvil) = if let Ok(endpoint) = std::env::var("TEST_EXTERNAL_ANVIL") {
            if config.block_time.is_some() {
                eyre::bail!("Cannot specify both block time and external anvil node");
            }
            (Url::from_str(&endpoint).wrap_err("Invalid endpoint on $TEST_EXTERNAL_ANVIL ")?, None)
        } else {
            let mut args = vec![];

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
                .args(["--odyssey", "--host", "0.0.0.0"].into_iter().chain(args.into_iter()))
                .try_spawn()
                .wrap_err("Failed to spawn Anvil")?;

            (anvil.endpoint_url(), Some(anvil))
        };

        // Load signers.
        let deployer = DynSigner::from_signing_key(
            "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
        )
        .await
        .wrap_err("Relay signer load failed")?;

        // Build provider
        let client = ClientBuilder::default().layer(RETRY_LAYER.clone()).http(endpoint.clone());
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(deployer.0.clone()))
            .connect_client(client);

        // fund relay signers
        for signer in DynSigner::derive_from_mnemonic(
            SIGNERS_MNEMONIC.parse()?,
            config.transaction_service_config.num_signers,
        )? {
            provider.anvil_set_balance(signer.address(), U256::from(1000e18)).await?;
        }

        // Get or deploy mock contracts.
        let (simulator, delegation, entrypoint, account_registry, erc20s, erc721) =
            get_or_deploy_contracts(&provider).await?;

        let eoa = if config.is_prep {
            EoaKind::create_prep()
        } else {
            EoaKind::create_upgraded(
                DynSigner::from_signing_key(
                    &std::env::var("TEST_EOA_PRIVATE_KEY").unwrap_or(EOA_PRIVATE_KEY.to_string()),
                )
                .await
                .wrap_err("EOA signer load failed")?,
            )
        };

        // fund EOA
        if !eoa.is_prep() {
            // mints erc20 and fee_token
            mint_erc20s(&erc20s[..2], &[eoa.address()], &provider).await?;

            provider
                .send_transaction(TransactionRequest {
                    to: Some(TxKind::Call(eoa.address())),
                    value: Some(U256::from(1000e18)),
                    ..Default::default()
                })
                .await?
                .get_receipt()
                .await?;
        }

        // Ensure our registry has our tokens
        let chain_id = provider.get_chain_id().await?;
        let mut registry = CoinRegistry::default();
        registry.extend(erc20s.iter().map(|erc20| ((chain_id, Some(*erc20)), CoinKind::USDT)));

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

        // Start relay service.
        let relay_handle = try_spawn(
            RelayConfig::default()
                .with_port(0)
                .with_metrics_port(0)
                .with_endpoints(&[endpoint.clone()])
                .with_quote_ttl(Duration::from_secs(60))
                .with_rate_ttl(Duration::from_secs(300))
                .with_signers_mnemonic(SIGNERS_MNEMONIC.parse().unwrap())
                .with_quote_constant_rate(1.0)
                .with_fee_tokens(&[erc20s.as_slice(), &[Address::ZERO]].concat())
                .with_entrypoint(entrypoint)
                .with_delegation_proxy(delegation)
                .with_account_registry(account_registry)
                .with_simulator(simulator)
                .with_user_op_gas_buffer(45_000) // todo: temp
                .with_tx_gas_buffer(30_000) // todo: temp
                .with_transaction_service_config(config.transaction_service_config)
                .with_database_url(database_url),
            registry,
        )
        .await?;

        let relay_endpoint = HttpClientBuilder::default()
            .build(relay_handle.http_url())
            .wrap_err("Failed to build relay client")?;

        let chain_id = provider.get_chain_id().await.wrap_err("Failed to get chain ID")?;

        Ok(Self {
            _anvil: anvil,
            provider: provider.erased(),
            eoa,
            entrypoint,
            delegation,
            fee_token: erc20s[1],
            erc20: erc20s[0],
            erc20s: erc20s[2..].to_vec(),
            erc721,
            chain_id,
            relay_endpoint,
            relay_handle,
        })
    }

    /// Sets [`Environment::fee_token`] to the native token.
    pub fn with_native_payment(mut self) -> Self {
        self.fee_token = Address::ZERO;
        self
    }

    /// Gets the on-chain EOA authorized keys.
    pub async fn get_eoa_authorized_keys(&self) -> eyre::Result<Vec<AuthorizeKeyResponse>> {
        Ok(self
            .relay_endpoint
            .get_keys(GetKeysParameters { address: self.eoa.address(), chain_id: self.chain_id })
            .await?)
    }

    /// Drops a transaction from the Anvil txpool and returns it.
    pub async fn drop_transaction(&self, hash: B256) -> Option<TxEnvelope> {
        let tx = self
            .provider
            .get_transaction_by_hash(hash)
            .await
            .unwrap()
            .map(|tx| tx.inner.into_inner());
        self.provider.anvil_drop_transaction(hash).await.unwrap();
        assert!(self.provider.get_transaction_by_hash(hash).await.unwrap().is_none());
        tx
    }

    /// Disables mining of blocks.
    ///
    /// Note: anvil does not expose API to disable mining so we're firstly switching it to auto
    /// mining and then disabling it. This means that this method would cause a block mined while
    /// executed.
    pub async fn disable_mining(&self) {
        self.provider.anvil_set_auto_mine(true).await.unwrap();
        self.provider.anvil_set_auto_mine(false).await.unwrap();
    }

    /// Enables mining of blocks.
    pub async fn enable_mining(&self) {
        self.provider.anvil_set_auto_mine(true).await.unwrap();
    }

    /// Mines a single block.
    pub async fn mine_block(&self) {
        self.provider.anvil_mine(None, None).await.unwrap();
    }

    /// Mines 10 blocks with dummy transactions with the given priority fee.
    ///
    /// Can be used to inflate the priority fee market.
    pub async fn mine_blocks_with_priority_fee(&self, priority_fee: u128) {
        for _ in 0..10 {
            let signer = PrivateKeySigner::from_signing_key(
                self._anvil.as_ref().unwrap().keys()[0].clone().into(),
            );
            let nonce = self.provider.get_transaction_count(signer.address()).await.unwrap();
            let max_fee_per_gas =
                self.provider.estimate_eip1559_fees().await.unwrap().max_fee_per_gas;

            join_all((0..10).map(|i| {
                let signer = &signer;
                async move {
                    let mut tx = TxEip1559 {
                        chain_id: self.chain_id,
                        nonce: nonce + i as u64,
                        to: Address::ZERO.into(),
                        gas_limit: 21000,
                        max_fee_per_gas: priority_fee + max_fee_per_gas,
                        max_priority_fee_per_gas: priority_fee,
                        ..Default::default()
                    };
                    let signature = (&signer).sign_transaction_sync(&mut tx).unwrap();
                    let tx = TxEnvelope::Eip1559(tx.into_signed(signature));

                    let _ = self.provider.send_raw_transaction(&tx.encoded_2718()).await.unwrap();
                }
            }))
            .await;

            self.mine_block().await;
        }
    }

    /// Fetches the current base_fee_per_gas and spawns a task setting blocks basefee to it.
    pub async fn freeze_basefee(&self) {
        // spawn
        let basefee = self
            .provider
            .get_block(Default::default())
            .await
            .unwrap()
            .unwrap()
            .header
            .base_fee_per_gas
            .unwrap() as u128;

        let provider = self.provider.clone();

        // spawn a task setting basefee for next block to a fixed value.
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                provider.anvil_set_next_block_base_fee_per_gas(basefee).await.unwrap();
            }
        });
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
) -> Result<(Address, Address, Address, Address, Vec<Address>, Address), eyre::Error> {
    let contracts_path = PathBuf::from(
        std::env::var("TEST_CONTRACTS").unwrap_or_else(|_| "tests/account/out".to_string()),
    );

    let mut entrypoint = deploy_contract(
        &provider,
        &contracts_path.join("EntryPoint.sol/EntryPoint.json"),
        Some(provider.default_signer_address().abi_encode().into()),
    )
    .await?;

    let delegation = deploy_contract(
        &provider,
        &contracts_path.join("Delegation.sol/Delegation.json"),
        Some(entrypoint.abi_encode().into()),
    )
    .await?;

    let mut delegation_proxy = deploy_contract(
        &provider,
        &contracts_path.join("EIP7702Proxy.sol/EIP7702Proxy.json"),
        Some((delegation, Address::ZERO).abi_encode().into()),
    )
    .await?;

    let mut account_registry = deploy_contract(
        &provider,
        &contracts_path.join("AccountRegistry.sol/AccountRegistry.json"),
        None,
    )
    .await?;

    let mut simulator =
        deploy_contract(&provider, &contracts_path.join("Simulator.sol/Simulator.json"), None)
            .await?;

    // Entrypoint
    if let Ok(address) = std::env::var("TEST_ENTRYPOINT") {
        entrypoint = Address::from_str(&address).wrap_err("Entrypoint address parse failed.")?;
    }

    // Delegation
    if let Ok(address) = std::env::var("TEST_DELEGATION") {
        delegation_proxy =
            Address::from_str(&address).wrap_err("Delegation address parse failed.")?
    }

    // Account Registry
    if let Ok(address) = std::env::var("TEST_ACCOUNT_REGISTRY") {
        account_registry =
            Address::from_str(&address).wrap_err("Account Registry address parse failed.")?
    }

    // Simulator
    if let Ok(address) = std::env::var("TEST_SIMULATOR") {
        simulator = Address::from_str(&address).wrap_err("Simulator address parse failed.")?
    }

    // Have at least 2 erc20 deployed
    let mut erc20s = Vec::with_capacity(2);
    if let Ok(entrypoint) = std::env::var("TEST_ERC20") {
        erc20s.push(Address::from_str(&entrypoint).wrap_err("ERC20 address parse failed.")?)
    };

    while erc20s.len() != 10 {
        let erc20 = deploy_contract(
            &provider,
            &contracts_path.join("MockERC20.sol/MockERC20.json"),
            Some(
                MockErc20::constructorCall {
                    name_: "mockName".to_string(),
                    symbol_: "mockSymbol".to_string(),
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

    Ok((simulator, delegation_proxy, entrypoint, account_registry, erc20s, erc721))
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
