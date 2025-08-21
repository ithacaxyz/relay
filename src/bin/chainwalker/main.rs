//! Chainwalker - A tool for walking through all chain connections to validate cross-chain
//! functionality.

mod report;
mod tester;
mod utils;

use alloy::primitives::{B256, ChainId};
use clap::Parser;
use eyre::{Result, eyre};
use jsonrpsee::http_client::HttpClientBuilder;
use relay::{
    signers::DynSigner,
    types::{KeyType, KeyWith712Signer},
};
use std::str::FromStr;
use tester::InteropTester;
use tracing::{info, level_filters::LevelFilter};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};
use url::Url;

/// Command line arguments for Chainwalker
#[derive(Debug, Parser)]
#[command(author, about = "Chainwalker - Walking through chain connections", long_about = None)]
pub struct Args {
    /// Private key of test account that will be used for testing
    #[arg(long = "private-key", value_name = "KEY", required = true, env = "PRIVATE_KEY")]
    private_key: String,

    /// Only test these specific interop token UIDs
    #[arg(long = "only-uids", value_delimiter = ',')]
    only_uids: Option<Vec<String>>,

    /// Only test these specific chains
    #[arg(long = "only-chains", value_delimiter = ',', conflicts_with = "exclude_chains")]
    only_chains: Option<Vec<ChainId>>,

    /// Exclude these chains from testing
    #[arg(long = "exclude-chains", value_delimiter = ',', conflicts_with = "only_chains")]
    exclude_chains: Option<Vec<ChainId>>,

    /// Plan and display the test sequence without executing transfers
    #[arg(long = "no-run")]
    no_run: bool,

    /// Continue even if account has been used before (only use if testing same account
    /// implementation)
    #[arg(long = "force")]
    force: bool,

    /// Percentage of balance to transfer (default: 90)
    #[arg(long = "transfer-percentage", default_value = "90")]
    transfer_percentage: u8,

    /// Skip waiting for settlement completion
    #[arg(long = "skip-settlement-wait")]
    skip_settlement_wait: bool,

    /// Relay URL (defaults to staging)
    #[arg(long = "relay-url", default_value = "https://stg-rpc.ithaca.xyz")]
    relay_url: Url,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder().with_default_directive(LevelFilter::INFO.into()).from_env_lossy(),
        )
        .init();

    let args = Args::parse();

    // Create InteropTester
    let test_account = DynSigner::from_signing_key(&args.private_key).await?;
    let relay_client = HttpClientBuilder::new().build(&args.relay_url)?;

    // Parse the private key to B256 for the mock key
    let private_key_bytes =
        if args.private_key.starts_with("0x") { &args.private_key[2..] } else { &args.private_key };
    let mock_key = B256::from_str(private_key_bytes)
        .map_err(|e| eyre!("Invalid private key format: {}", e))?;

    // Create the account key using Secp256k1 with the same private key
    let account_key = KeyWith712Signer::mock_admin_with_key(KeyType::Secp256k1, mock_key)?
        .ok_or_else(|| eyre!("Failed to create account key"))?;

    info!("Initialized Chainwalker for address: {}", test_account.address());

    let mut tester = InteropTester {
        test_account,
        relay_client,
        only_uids: args.only_uids,
        only_chains: args.only_chains,
        exclude_chains: args.exclude_chains,
        transfer_percentage: args.transfer_percentage,
        no_run: args.no_run,
        skip_settlement_wait: args.skip_settlement_wait,
        account_key,
    };

    let _report = tester.run(args.force).await?;

    Ok(())
}
