//! Relay end-to-end test constants

use super::{eoa::EoaKind, *};
use alloy::{
    hex,
    network::EthereumWallet,
    node_bindings::{Anvil, AnvilInstance},
    primitives::{Address, Bytes, TxKind, U256},
    providers::{DynProvider, Provider, ProviderBuilder, WalletProvider},
    rpc::types::TransactionRequest,
    sol_types::{SolConstructor, SolValue},
};
use eyre::{self, ContextCompat, WrapErr};
use jsonrpsee::{
    http_client::{HttpClient, HttpClientBuilder},
    server::ServerHandle,
};
use relay::{
    config::RelayConfig,
    signers::DynSigner,
    spawn::try_spawn,
    types::{
        CoinKind, CoinRegistry, Entry, KeyWith712Signer,
        rpc::{AuthorizeKeyResponse, GetKeysParameters},
    },
};
use std::{
    net::TcpListener,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};
use url::Url;

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
    #[allow(dead_code)]
    pub relay_handle: ServerHandle,
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
        Self::setup(true).await
    }

    /// Sets up the test environment with a upgraded account using [`DynSigner`].
    ///
    /// Read [`Self::setup`] for more information on setup.
    pub async fn setup_with_upgraded() -> eyre::Result<Self> {
        Self::setup(false).await
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
    async fn setup(is_prep: bool) -> eyre::Result<Self> {
        dotenv::dotenv().ok();

        // Spawns a local Ethereum node if one is not specified.
        let (endpoint, anvil) = if let Ok(endpoint) = std::env::var("TEST_EXTERNAL_ANVIL") {
            (Url::from_str(&endpoint).wrap_err("Invalid endpoint on $TEST_EXTERNAL_ANVIL ")?, None)
        } else {
            let mut args = vec![];

            let fork_url = std::env::var("TEST_FORK_URL");
            if let Ok(fork_url) = &fork_url {
                args.extend(["--fork-url", fork_url]);
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
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(deployer.0.clone()))
            .on_http(endpoint.clone());

        // Get or deploy mock contracts.
        let (delegation, entrypoint, erc20s) = get_or_deploy_contracts(&provider).await?;

        let eoa = if is_prep {
            // Generate a random admin key from a random key type.
            let key_type = [KeyType::Secp256k1, KeyType::WebAuthnP256];
            let random_key_type = key_type[B256::random()[0] as usize % 2];

            EoaKind::create_prep(
                KeyWith712Signer::random_admin(random_key_type)?.unwrap(),
                delegation,
            )
            .await?
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

        mint_erc20s(&erc20s, &[eoa.address()], &provider).await?;

        // Ensure our registry has our tokens
        let chain_id = provider.get_chain_id().await?;
        let mut registry = CoinRegistry::default();
        registry.extend(erc20s.iter().map(|erc20| ((chain_id, Some(*erc20)), CoinKind::USDT)));

        // Fund relay signer and EOA
        let relay_private_key = RELAY_PRIVATE_KEY.to_string();
        let relay_signer =
            DynSigner::load(&relay_private_key, None).await.wrap_err("Relay signer load failed")?;

        for address in [relay_signer.address(), eoa.address()] {
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
        let relay_port = get_available_port()?;
        let relay_handle = try_spawn(
            RelayConfig::default()
                .with_port(relay_port)
                .with_metrics_port(0)
                .with_endpoints(&[endpoint.clone()])
                .with_quote_ttl(Duration::from_secs(60))
                .with_quote_key(relay_private_key.clone())
                .with_transaction_key(relay_private_key)
                .with_quote_constant_rate(1.0)
                .with_fee_tokens(&[erc20s.as_slice(), &[Address::ZERO]].concat())
                .with_entrypoint(entrypoint)
                .with_user_op_gas_buffer(100_000)
                .with_tx_gas_buffer(50_000), // todo: temp
            registry,
        )
        .await?;

        let relay_endpoint = HttpClientBuilder::default()
            .build(format!("http://localhost:{relay_port}"))
            .wrap_err("Failed to build relay client")?;

        let chain_id = provider.get_chain_id().await.wrap_err("Failed to get chain ID")?;

        Ok(Self {
            _anvil: anvil,
            provider: provider.erased(),
            eoa,
            entrypoint,
            delegation,
            fee_token: erc20s[0],
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

    /// Returns an [`Entry`].
    pub fn entry(&self) -> Entry<DynProvider> {
        Entry::new(self.entrypoint, self.provider.clone())
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
                    name_: Default::default(),
                    symbol_: Default::default(),
                    decimals_: Default::default(),
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

/// Finds an available port by binding to "127.0.0.1:0".
fn get_available_port() -> std::io::Result<u16> {
    // Binding to port 0 tells the OS to assign an available port.
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}
