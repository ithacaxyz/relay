//! Test that spawns e2e environment for stress testing

mod e2e;

use alloy::{
    primitives::ChainId,
    providers::{Provider, ext::AnvilApi},
};
use alloy_primitives::{b256, B256};
use bytes::Bytes;
use e2e::{DEPLOYER_PRIVATE_KEY, Environment, EnvironmentConfig, mint_erc20s};
use futures_util::future::try_join_all;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use tokio::net::TcpListener;

/// Simple JSON-RPC proxy that forwards eth_* calls to one URL and everything else to another
async fn spawn_proxy_server(
    eth_provider_url: String,
    relay_url: String,
    port: u16,
) -> eyre::Result<SocketAddr> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(addr).await?;
    let addr = listener.local_addr()?;

    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let io = TokioIo::new(tcp);
            let eth_url = eth_provider_url.clone();
            let relay_url = relay_url.clone();

            tokio::spawn(async move {
                let service = service_fn(move |req| {
                    let eth_url = eth_url.clone();
                    let relay_url = relay_url.clone();
                    forward_request(req, eth_url, relay_url)
                });

                if let Err(err) =
                    hyper::server::conn::http1::Builder::new().serve_connection(io, service).await
                {
                    eprintln!("Error serving connection: {:?}", err);
                }
            });
        }
    });

    Ok(addr)
}

async fn forward_request(
    req: Request<Incoming>,
    eth_url: String,
    relay_url: String,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Read the request body
    let body_bytes = req.collect().await?.to_bytes();
    let body_str = String::from_utf8_lossy(&body_bytes);

    // Determine target based on method
    let target_url = if body_str.contains("\"method\":\"eth_") { eth_url } else { relay_url };

    // Forward the request
    let client = reqwest::Client::new();
    let resp = match client
        .post(&target_url)
        .header("content-type", "application/json")
        .body(body_bytes.to_vec())
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            let error_body = format!(
                r#"{{"jsonrpc":"2.0","error":{{"code":-32603,"message":"Proxy error: {}"}}}}"#,
                e
            );
            return Ok(Response::builder()
                .status(502)
                .body(Full::new(Bytes::from(error_body)))
                .unwrap());
        }
    };

    let status = resp.status();
    let body = resp.bytes().await.unwrap_or_default();

    Ok(Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(body))
        .unwrap())
}

/// Test that spawns the e2e environment and keeps it alive for stress testing
///
/// Usage:
/// ```bash
/// # Default: 3 chains, no new account
/// TEST_CONTRACTS=tests/account/out cargo test --test spawn_e2e_env -- --ignored --nocapture
///
/// # With environment variables
/// NUM_CHAINS=2 FUND_ACCOUNT=1 TEST_CONTRACTS=tests/account/out cargo test --test spawn_e2e_env -- --ignored --nocapture
/// ```
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn spawn_e2e_env() -> eyre::Result<()> {
    // Read configuration from environment variables
    let num_chains = std::env::var("NUM_CHAINS").ok().and_then(|s| s.parse().ok()).unwrap_or(3);

    let fund_account =
        std::env::var("FUND_ACCOUNT").ok().map(|s| s == "1" || s == "true").unwrap_or(false);

    println!("Starting e2e environment with {} chains...", num_chains);

    let config = EnvironmentConfig {
        num_chains,
        transaction_service_config: relay::config::TransactionServiceConfig {
            num_signers: 10,
            ..Default::default()
        },
        ..Default::default()
    };

    let env = Environment::setup_with_config(config).await?;

    println!("\n================================");
    println!("E2E ENVIRONMENT READY");
    println!("================================\n");

    println!("RELAY CONFIGURATION:");
    println!("  URL: {}", env.relay_handle.http_url());
    println!("  Metrics: http://127.0.0.1:9000/metrics");
    println!();

    let rpc_urls = env.get_rpc_urls().unwrap();

    // Get chain IDs for each RPC URL
    let url_chain_pairs: Vec<(String, ChainId)> =
        try_join_all(rpc_urls.iter().enumerate().map(async |(i, url)| {
            let chain_id = env.providers[i].get_chain_id().await?;
            Ok::<_, eyre::Report>((url.clone(), chain_id))
        }))
        .await
        .unwrap();

    println!("CHAIN CONFIGURATIONS:");
    for (i, (rpc_url, chain_id)) in url_chain_pairs.iter().enumerate() {
        println!("\nChain {} (ID: {}):", i + 1, chain_id);
        println!("  RPC URL: {}", rpc_url);
        println!("  Fee Token: {:?}", env.fee_token);
        println!("  ERC20 Token: {:?}", env.erc20);
        println!("  Native Token: 0x0000000000000000000000000000000000000000");
    }

    println!("\nCONTRACT ADDRESSES:");
    println!("  Orchestrator: {:?}", env.orchestrator);
    println!("  Delegation: {:?}", env.delegation);
    println!("  Funder: {:?}", env.funder);
    println!("  Escrow: {:?}", env.escrow);
    println!("  Settler: {:?}", env.settler);

    // Create a new stress test account if requested
    let (stress_address, stress_private_key) = if fund_account {
        let stress_signer = alloy::signers::local::PrivateKeySigner::from_slice(B256::random().as_slice()).unwrap();
        let stress_address = stress_signer.address();
        let stress_private_key = alloy::hex::encode(stress_signer.to_bytes());

        println!("\nFUNDING STRESS TEST ACCOUNT...");

        // Fund the stress test account on all chains
        for (i, provider) in env.providers.iter().enumerate() {
            // Fund with ETH
            provider
                .anvil_set_balance(stress_address, alloy::primitives::U256::from(1000e18))
                .await?;

            // Use mint_erc20s to fund with tokens
            mint_erc20s(&[env.fee_token, env.erc20], &[stress_address], provider).await?;

            println!("  Chain {} funded ✓", i + 1);
        }

        println!("\nSTRESS TEST ACCOUNT:");
        println!("  Address: {:?}", stress_address);
        println!("  Private Key: 0x{}", stress_private_key);
        println!();

        (stress_address, stress_private_key)
    } else {
        // Use deployer account if no funding requested
        (env.deployer.address(), format!("{:x}", DEPLOYER_PRIVATE_KEY))
    };

    // Spawn proxy servers for each chain
    println!("\n================================");
    println!("SPAWNING PROXY SERVERS");
    println!("================================\n");

    println!("Creating proxy servers that route calls based on method:");
    println!("- eth_* methods → chain RPC (for chain-specific calls)");
    println!("- other methods → relay (for account abstraction)");
    println!();

    let mut proxy_addresses = Vec::new();
    let base_port = 9545; // Start from port 9545

    for (i, (rpc_url, chain_id)) in url_chain_pairs.iter().enumerate() {
        let port = base_port + i as u16;

        // Convert ws:// to http:// for the proxy
        let http_rpc_url = rpc_url.replace("ws://", "http://").replace("wss://", "https://");

        let proxy_addr =
            spawn_proxy_server(http_rpc_url.clone(), env.relay_handle.http_url(), port).await?;

        proxy_addresses.push(proxy_addr);
        println!("Proxy {} (Chain ID {}): http://{}", i, chain_id, proxy_addr);
        println!("  → eth_* calls forwarded to: {}", http_rpc_url);
        println!("  → other calls forwarded to: {}", env.relay_handle.http_url());
        println!();
    }

    // Print example stress test commands
    println!("\n================================");
    println!("STRESS TEST EXAMPLES");
    println!("================================");

    if !fund_account {
        println!("\nUsing deployer account: {:?}", stress_address);
        println!("To create and fund a new account, run with FUND_ACCOUNT=1");
    }
    println!();

    for ((_, chain_id), proxy_addr) in url_chain_pairs.iter().zip(proxy_addresses.iter()) {
        println!("# Stress test for chain ID {} via proxy", chain_id);
        println!("cargo run --bin stress -- \\");
        println!("  --rpc-url http://{} \\", proxy_addr);
        println!("  --fee-token {:?} \\", env.fee_token);
        println!("  --private-key 0x{} \\", stress_private_key);
        println!("  --accounts 100");
        println!();
    }

    println!("# Multi-chain stress test (all chains via proxies):");
    let proxy_urls: Vec<String> =
        proxy_addresses.iter().map(|addr| format!("http://{}", addr)).collect();

    println!("cargo run --bin stress -- \\");
    for proxy_url in &proxy_urls {
        println!("  --rpc-url {} \\", proxy_url);
    }
    println!("  --fee-token {:?} \\", env.fee_token);
    println!("  --private-key 0x{} \\", stress_private_key);
    println!("  --accounts 100");

    println!("\n================================");
    println!("Environment is running. Press Ctrl+C to shutdown.");
    println!("================================\n");

    // Keep running until interrupted
    tokio::signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
    println!("\nShutting down e2e environment...");

    Ok(())
}
