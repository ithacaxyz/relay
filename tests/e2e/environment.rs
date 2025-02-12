//! Relay end-to-end test constants

use super::*;
use alloy::{
    hex,
    network::EthereumWallet,
    node_bindings::{Anvil, AnvilInstance},
    primitives::{address, Address, Bytes, TxKind, U256},
    providers::{ext::AnvilApi, Provider, ProviderBuilder, WalletProvider},
    rpc::types::TransactionRequest,
    signers::Signer,
    sol_types::{SolCall, SolConstructor, SolEvent, SolValue},
};
use alloy_chains::NamedChain;
use eyre::{self, ContextCompat, OptionExt, WrapErr};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use relay::{cli::Args, signer::LocalOrAws, types::CoinKind};
use std::{
    net::Ipv4Addr,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::time::sleep;

pub struct Environment {
    pub _anvil: AnvilInstance,
    pub provider: Box<dyn Provider>,
    pub eoa_signer: LocalOrAws,
    pub entrypoint: Address,
    pub delegation: Address,
    pub erc20: Address,
    pub chain_id: u64,
    pub relay_endpoint: HttpClient,
    pub relay_handle: tokio::task::JoinHandle<eyre::Result<()>>,
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
        let upstream = anvil.endpoint_url();
        let entrypoint = address!("307AF7d28AfEE82092aA95D35644898311CA5360");

        // Load signers.
        let relay_signer = LocalOrAws::load(&RELAY_PRIVATE_KEY.to_string(), None)
            .await
            .wrap_err("Relay signer load failed")?;
        let eoa_signer = LocalOrAws::load(&EOA_PRIVATE_KEY.to_string(), None)
            .await
            .wrap_err("EOA signer load failed")?;

        // Build provider
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(relay_signer.clone()))
            .on_http(upstream.clone());

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
                .call()
                .await
                .wrap_err("Minting failed")?;
        }

        // Temporary assertion until we can dynamically initialize COINS_CONFIG
        assert!(CoinKind::get_token(NamedChain::AnvilHardhat.into(), erc20).is_some());

        // Start relay service.
        let relay_handle = tokio::spawn(async move {
            let cli = Args {
                address: std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 3131,
                upstream,
                quote_ttl: Duration::from_secs(60),
                quote_secret_key: RELAY_PRIVATE_KEY.to_string(),
                fee_tokens: vec![erc20],
                secret_key: RELAY_PRIVATE_KEY.to_string(),
            };
            cli.run().await
        });

        // Wait for it to boot
        // todo: health endpoint
        sleep(Duration::from_secs(1)).await;

        let relay_endpoint = HttpClientBuilder::default()
            .build("http://localhost:3131")
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

    /// Cleanup the environment, ensuring the relay task is shutdown
    pub async fn cleanup(self) {
        self.relay_handle.abort();
        let _ = self.relay_handle.await;
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
