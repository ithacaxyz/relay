//! Relay end-to-end test constants

use super::{eoa::EoaKind, *};
use alloy::{
    consensus::{SignableTransaction, TxEip1559, TxEnvelope},
    eips::Encodable2718,
    hex,
    network::{EthereumWallet, TxSignerSync},
    node_bindings::{Anvil, AnvilInstance},
    primitives::{Address, Bytes, TxKind, U256},
    providers::{DynProvider, Provider, ProviderBuilder, WalletProvider, ext::AnvilApi},
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
use std::{
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};
use url::Url;

/// All settings for configuring the [`Environment`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct EnvironmentConfig {
    pub is_prep: bool,
    pub block_time: Option<f64>,
    pub signers: Vec<B256>,
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
            signers: vec![RELAY_PRIVATE_KEY],
            transaction_service_config: Default::default(),
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
    pub fee_token: Address,
    pub erc20: Address,
    pub erc20_alt: Address,
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
    /// - `TEST_ERC20`: Address for ERC20 token; deploys a mock if unset.
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
    /// TEST_ERC20="0xYourErc20Address"
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
        let deployer = DynSigner::load(
            "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
            None,
        )
        .await
        .wrap_err("Relay signer load failed")?;

        // Build provider
        let client = ClientBuilder::default().layer(RETRY_LAYER.clone()).http(endpoint.clone());
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(deployer.0.clone()))
            .on_client(client);

        // Get or deploy mock contracts.
        let (delegation, entrypoint, erc20s) = get_or_deploy_contracts(&provider).await?;

        let eoa = if config.is_prep {
            EoaKind::create_prep()
        } else {
            EoaKind::create_upgraded(
                DynSigner::load(
                    &std::env::var("TEST_EOA_PRIVATE_KEY").unwrap_or(EOA_PRIVATE_KEY.to_string()),
                    None,
                )
                .await
                .wrap_err("EOA signer load failed")?,
            )
        };

        if !eoa.is_prep() {
            mint_erc20s(&erc20s, &[eoa.address()], &provider).await?;
        }

        // Ensure our registry has our tokens
        let chain_id = provider.get_chain_id().await?;
        let mut registry = CoinRegistry::default();
        registry.extend(erc20s.iter().map(|erc20| ((chain_id, Some(*erc20)), CoinKind::USDT)));

        // Fund relay signers and EOA
        let relay_signers =
            config.signers.iter().map(|s| PrivateKeySigner::from_bytes(s).unwrap().address());
        let fundable_addresses = if eoa.is_prep() {
            relay_signers.collect::<Vec<_>>()
        } else {
            relay_signers.chain(iter::once(eoa.address())).collect()
        };

        for address in fundable_addresses {
            provider
                .send_transaction(TransactionRequest {
                    to: Some(TxKind::Call(address)),
                    value: Some(U256::from(1000e18)),
                    ..Default::default()
                })
                .await?
                .get_receipt()
                .await?;
        }

        // Start relay service.
        let relay_handle = try_spawn(
            RelayConfig::default()
                .with_port(0)
                .with_metrics_port(0)
                .with_endpoints(&[endpoint.clone()])
                .with_quote_ttl(Duration::from_secs(60))
                .with_rate_ttl(Duration::from_secs(300))
                .with_quote_key(config.signers[0].clone().to_string())
                .with_transaction_keys(
                    &config.signers.into_iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                )
                .with_quote_constant_rate(1.0)
                .with_fee_tokens(&[erc20s.as_slice(), &[Address::ZERO]].concat())
                .with_entrypoint(entrypoint)
                .with_user_op_gas_buffer(40_000) // todo: temp
                .with_tx_gas_buffer(50_000) // todo: temp
                .with_transaction_service_config(config.transaction_service_config)
                .with_database_url(std::env::var("DATABASE_URL").ok()),
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
            erc20_alt: erc20s[1],
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
) -> Result<(Address, Address, Vec<Address>), eyre::Error> {
    let contracts_path = PathBuf::from(
        std::env::var("TEST_CONTRACTS").unwrap_or_else(|_| "tests/account/out".to_string()),
    );
    let mut entrypoint = deploy_contract(
        &provider,
        &contracts_path.join("EntryPoint.sol/EntryPoint.json"),
        Some(provider.default_signer_address().abi_encode().into()),
    )
    .await?;
    let mut delegation = deploy_contract(
        &provider,
        &contracts_path.join("Delegation.sol/Delegation.json"),
        Some(entrypoint.abi_encode().into()),
    )
    .await?;

    // Entrypoint
    if let Ok(address) = std::env::var("TEST_ENTRYPOINT") {
        entrypoint = Address::from_str(&address).wrap_err("Entrypoint address parse failed.")?;
    }

    // Delegation
    if let Ok(address) = std::env::var("TEST_DELEGATION") {
        delegation = Address::from_str(&address).wrap_err("Delegation address parse failed.")?
    }

    // Have at least 2 erc20 deployed
    let mut erc20s = Vec::with_capacity(2);
    if let Ok(entrypoint) = std::env::var("TEST_ERC20") {
        erc20s.push(Address::from_str(&entrypoint).wrap_err("ERC20 address parse failed.")?)
    };

    while erc20s.len() != 2 {
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
    Ok((delegation, entrypoint, erc20s))
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
