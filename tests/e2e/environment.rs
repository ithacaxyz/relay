//! Relay end-to-end test constants

use super::*;
use alloy::{
    hex,
    network::EthereumWallet,
    node_bindings::{Anvil, AnvilInstance},
    primitives::{Address, Bytes, TxKind, U256, address},
    providers::{Provider, ProviderBuilder, WalletProvider, ext::AnvilApi},
    rpc::types::TransactionRequest,
    signers::Signer,
    sol_types::{SolCall, SolConstructor, SolEvent, SolValue},
};
use alloy_chains::NamedChain;
use eyre::{self, ContextCompat, OptionExt, WrapErr};
use jsonrpsee::{
    http_client::{HttpClient, HttpClientBuilder},
    server::ServerHandle,
};
use relay::{
    cli::Args,
    config::RelayConfig,
    signers::{DynSigner, P256Signer},
    spawn::try_spawn,
    types::CoinKind,
};
use std::{
    net::{Ipv4Addr, TcpListener},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::time::sleep;

pub struct Environment {
    pub _anvil: AnvilInstance,
    pub provider: Box<dyn Provider>,
    pub eoa_signer: DynSigner,
    pub entrypoint: Address,
    pub delegation: Address,
    pub erc20: Address,
    pub chain_id: u64,
    pub relay_endpoint: HttpClient,
    pub relay_handle: ServerHandle,
}

impl std::fmt::Debug for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Environment")
            .field("eoa_signer", &self.eoa_signer.address())
            .field("entrypoint", &self.entrypoint)
            .field("delegation", &self.delegation)
            .field("erc20", &self.erc20)
            .field("chain_id", &self.chain_id)
            .field("relay_endpoint", &self.relay_endpoint)
            .finish()
    }
}

impl Environment {
    /// Sets up the test environment including Anvil, contracts, and the relay service.
    pub async fn setup() -> eyre::Result<Self> {
        // Spawn local Ethereum node.
        let anvil = Anvil::new()
            .args(["--odyssey", "--host", "0.0.0.0"])
            .try_spawn()
            .wrap_err("Failed to spawn Anvil")?;
        let endpoint = anvil.endpoint_url();
        let entrypoint = address!("307AF7d28AfEE82092aA95D35644898311CA5360");

        // Load signers.
        let relay_signer = DynSigner::load(&RELAY_PRIVATE_KEY.to_string(), None)
            .await
            .wrap_err("Relay signer load failed")?;
        let eoa_signer = DynSigner::load(&EOA_PRIVATE_KEY.to_string(), None)
            .await
            .wrap_err("EOA signer load failed")?;

        // Build provider
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(relay_signer.0.clone()))
            .on_http(endpoint.clone());

        // Deploy contracts.
        let contracts_path = PathBuf::from(
            std::env::var("CONTRACTS").unwrap_or_else(|_| "tests/account/out".to_string()),
        );
        let mock_entrypoint =
            setup_contract(&provider, &contracts_path.join("EntryPoint.sol/EntryPoint.json"), None)
                .await?;
        let delegation =
            setup_contract(&provider, &contracts_path.join("Delegation.sol/Delegation.json"), None)
                .await?;
        let erc20 = setup_contract(
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

        provider
            .anvil_set_code(entrypoint, provider.get_code_at(mock_entrypoint).await?)
            .await
            .wrap_err("Failed to set code")?;

        // Mint tokens for both signers.
        for signer in [&relay_signer, &eoa_signer] {
            MockErc20::new(erc20, &provider)
                .mint(signer.address(), U256::from(100e18))
                .send()
                .await
                .wrap_err("Minting failed")?;
        }

        // Temporary assertion until we can dynamically initialize COINS_CONFIG
        assert!(CoinKind::get_token(NamedChain::AnvilHardhat.into(), erc20).is_some());

        // Start relay service.
        let relay_handle = try_spawn(
            RelayConfig::default()
                .with_port(get_available_port()?)
                .with_endpoints(vec![endpoint.clone()])
                .with_quote_ttl(Duration::from_secs(60))
                .with_quote_secret_key(RELAY_PRIVATE_KEY.to_string())
                .with_secret_key(RELAY_PRIVATE_KEY.to_string())
                .with_fee_tokens(vec![erc20]),
            None,
        )
        .await?;

        // Wait for it to boot
        // todo: health endpoint
        sleep(Duration::from_secs(1)).await;

        let relay_endpoint = HttpClientBuilder::default()
            .build(format!("http://localhost:{relay_port}"))
            .wrap_err("Failed to build relay client")?;

        let chain_id = provider.get_chain_id().await.wrap_err("Failed to get chain ID")?;

        Ok(Self {
            _anvil: anvil,
            provider: Box::new(provider),
            eoa_signer,
            entrypoint,
            delegation,
            erc20,
            chain_id,
            relay_endpoint,
            relay_handle,
        })
    }
}

async fn setup_contract<P: Provider>(
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
