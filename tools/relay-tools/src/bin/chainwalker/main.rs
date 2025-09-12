//! Chainwalker - A tool for walking through all chain connections to validate cross-chain
//! functionality.

mod report;
mod tester;
mod utils;

use alloy::primitives::ChainId;
use clap::Parser;
use eyre::Result;
use jsonrpsee::http_client::HttpClientBuilder;
use relay::{
    signers::DynSigner,
    types::{KeyWith712Signer, U40},
};
use relay_tools::common::init_logging;
use tester::InteropTester;
use tracing::info;
use url::Url;

/// Command line arguments for Chainwalker
#[derive(Debug, Parser)]
#[command(author, about = "Chainwalker - Walking through chain connections", long_about = None)]
pub struct Args {
    /// Mnemonic phrase for accounts that will be used for testing.
    ///
    /// Two keys will be derived from this mnemonic:
    /// - Root EOA key
    /// - Custom account key to use when `--use-root-key` is not used
    #[arg(long = "mnemonic", value_name = "PHRASE", required = true, env = "MNEMONIC")]
    mnemonic: String,

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
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();

    let args = Args::parse();

    let mut signers = DynSigner::derive_from_mnemonic(args.mnemonic.parse()?, 2)?;
    let test_account = signers.remove(0);
    let account_signer = signers.remove(0);

    let account_key = KeyWith712Signer::secp256k1_from_signer(account_signer, U40::ZERO, true);

    let relay_client = HttpClientBuilder::new().build(&args.relay_url)?;

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
