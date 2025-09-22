//! Chainwalker - A tool for walking through all chain connections to validate cross-chain
//! functionality.

mod report;
mod tester;
mod utils;

use alloy::primitives::{ChainId, keccak256};
use clap::{Parser, ValueEnum};
use eyre::{OptionExt, Result};
use jsonrpsee::http_client::HttpClientBuilder;
use relay::{
    signers::DynSigner,
    types::{KeyType, KeyWith712Signer},
};
use relay_tools::common::init_logging_with_color;
use std::fmt::{self, Display};
use tester::InteropTester;
use tracing::info;
use url::Url;

/// The color mode for the cli.
#[derive(Debug, Copy, Clone, ValueEnum, Eq, PartialEq)]
pub enum ColorMode {
    /// Colors on
    Always,
    /// Colors off
    Never,
}

impl ColorMode {
    /// Returns true if colors should be enabled
    pub fn use_color(&self) -> bool {
        matches!(self, Self::Always)
    }
}

impl Display for ColorMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Always => write!(f, "always"),
            Self::Never => write!(f, "never"),
        }
    }
}

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

    /// Do not pass a separate `key` to `prepareCalls` requests and use the root EOA key instead
    #[arg(long = "use-root-key")]
    use_root_key: bool,

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

    /// Sets whether or not the formatter emits ANSI terminal escape codes for colors and other
    /// text formatting
    ///
    /// Possible values:
    /// - always: Colors on
    /// - never:  Colors off
    #[arg(long = "color", value_enum, default_value = "always")]
    color: ColorMode,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging with color mode
    init_logging_with_color(args.color.use_color());

    // Create InteropTester
    let test_account = DynSigner::from_signing_key(&args.private_key).await?;
    let relay_client = HttpClientBuilder::new().build(&args.relay_url)?;
    // Derive an account key that will be authorized in porto account, it's different from the root
    // EOA key
    let account_key =
        KeyWith712Signer::mock_admin_with_key(KeyType::Secp256k1, keccak256(&args.private_key))?
            .ok_or_eyre("Failed to create account key")?;

    info!("Initialized Chainwalker for address: {}", test_account.address());

    // Create InteropTester
    let mut tester = InteropTester {
        test_account,
        account_key,
        relay_client,
        only_uids: args.only_uids,
        only_chains: args.only_chains,
        exclude_chains: args.exclude_chains,
        transfer_percentage: args.transfer_percentage,
        no_run: args.no_run,
        use_root_key: args.use_root_key,
        skip_settlement_wait: args.skip_settlement_wait,
    };

    let _report = tester.run(args.force).await?;

    Ok(())
}
