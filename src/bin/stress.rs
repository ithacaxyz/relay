//! Relay stress testing tool.
//!
//! # Example
//!
//! ```sh
//! cargo r --bin stress -- --relay-url https://relay-staging.ithaca.xyz --private-key $PRIVATE_KEY --chain-id 28403 --fee-token 0x541a5505620A658932e326D0dC996C460f5AcBE1 --rpc-url https://odyssey-devnet.ithaca.xyz --accounts 500
//! ```
//! The test script will transfer the fee token out of the account specified in --private-key, so it
//! must have enough balance to cover for the accounts. The amount sent to each account is
//! configurable
// it will first create all the accounts and fund them - might take a while.

use std::time::Duration;

use alloy::{
    network::EthereumWallet,
    primitives::{Address, B256, ChainId, U256, address, bytes, keccak256},
    providers::{
        Provider, ProviderBuilder,
        fillers::{CachedNonceManager, ChainIdFiller, GasFiller, NonceFiller},
    },
    rpc::types::TransactionRequest,
    sol_types::SolValue,
};
use alloy_chains::Chain;
use clap::Parser;
use eyre::Context;
use futures_util::{StreamExt, future::try_join_all, stream::FuturesUnordered};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use relay::{
    rpc::RelayApiClient,
    signers::{DynSigner, Eip712PayLoadSigner},
    types::{
        Call,
        IERC20::IERC20Instance,
        KeyType, KeyWith712Signer,
        rpc::{
            Meta, PrepareCallsCapabilities, PrepareCallsParameters, PrepareCallsResponse,
            PrepareUpgradeAccountParameters, PrepareUpgradeAccountResponse,
            UpgradeAccountCapabilities, UpgradeAccountParameters, UpgradeAccountSignatures,
        },
    },
};
use tokio::time::Instant;
use tracing::{error, info, level_filters::LevelFilter, trace};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};
use url::Url;

alloy::sol! {
    /// <https://github.com/omniaprotocol/disperse.app/blob/main/Disperse.sol>
    /// Bytecode from <https://basescan.org/tx/0x6183b11e486313c20c8f8421b858fba9b2af089963b0e52d2485bf0ca7471fb5>
    #[sol(rpc, bytecode = "0x608060405234801561001057600080fd5b506106f4806100206000396000f300608060405260043610610057576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806351ba162c1461005c578063c73a2d60146100cf578063e63d38ed14610142575b600080fd5b34801561006857600080fd5b506100cd600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803590602001908201803590602001919091929391929390803590602001908201803590602001919091929391929390505050610188565b005b3480156100db57600080fd5b50610140600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803590602001908201803590602001919091929391929390803590602001908201803590602001919091929391929390505050610309565b005b6101866004803603810190808035906020019082018035906020019190919293919293908035906020019082018035906020019190919293919293905050506105b0565b005b60008090505b84849050811015610301578573ffffffffffffffffffffffffffffffffffffffff166323b872dd3387878581811015156101c457fe5b9050602002013573ffffffffffffffffffffffffffffffffffffffff1686868681811015156101ef57fe5b905060200201356040518463ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018281526020019350505050602060405180830381600087803b1580156102ae57600080fd5b505af11580156102c2573d6000803e3d6000fd5b505050506040513d60208110156102d857600080fd5b810190808051906020019092919050505015156102f457600080fd5b808060010191505061018e565b505050505050565b60008060009150600090505b8585905081101561034657838382818110151561032e57fe5b90506020020135820191508080600101915050610315565b8673ffffffffffffffffffffffffffffffffffffffff166323b872dd3330856040518463ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018281526020019350505050602060405180830381600087803b15801561041d57600080fd5b505af1158015610431573d6000803e3d6000fd5b505050506040513d602081101561044757600080fd5b8101908080519060200190929190505050151561046357600080fd5b600090505b858590508110156105a7578673ffffffffffffffffffffffffffffffffffffffff1663a9059cbb878784818110151561049d57fe5b9050602002013573ffffffffffffffffffffffffffffffffffffffff1686868581811015156104c857fe5b905060200201356040518363ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200182815260200192505050602060405180830381600087803b15801561055457600080fd5b505af1158015610568573d6000803e3d6000fd5b505050506040513d602081101561057e57600080fd5b8101908080519060200190929190505050151561059a57600080fd5b8080600101915050610468565b50505050505050565b600080600091505b858590508210156106555785858381811015156105d157fe5b9050602002013573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166108fc858585818110151561061557fe5b905060200201359081150290604051600060405180830381858888f19350505050158015610647573d6000803e3d6000fd5b5081806001019250506105b8565b3073ffffffffffffffffffffffffffffffffffffffff1631905060008111156106c0573373ffffffffffffffffffffffffffffffffffffffff166108fc829081150290604051600060405180830381858888f193505050501580156106be573d6000803e3d6000fd5b505b5050505050505600a165627a7a723058204f25a733917e0bf639cd1e101d55bd927f843fb395fb2a963a7909c09ae023ed0029")]
    contract Disperse {
        function disperseToken(address token, address[] recipients, uint256[] values) external;
    }
}

const CREATE2_DEPLOYER: Address = address!("0x4e59b44847b379578588920cA78FbF26c0B4956C");

#[derive(Clone, Debug)]
struct StressAccount {
    address: Address,
    key: KeyWith712Signer,
}

impl StressAccount {
    fn new(address: Address, key: KeyWith712Signer) -> Self {
        Self { address, key }
    }
}

impl StressAccount {
    async fn run(
        self,
        chain_id: ChainId,
        fee_token: Address,
        relay_client: HttpClient,
    ) -> eyre::Result<()> {
        let mut previous_nonce = None;
        let mut retries = 5;
        loop {
            let prepare_start = Instant::now();
            let PrepareCallsResponse { context, digest, .. } = match relay_client
                .prepare_calls(PrepareCallsParameters {
                    required_funds: vec![],
                    calls: vec![Call { to: Address::ZERO, value: U256::ZERO, data: bytes!("") }],
                    chain_id,
                    from: Some(self.address),
                    capabilities: PrepareCallsCapabilities {
                        authorize_keys: vec![],
                        meta: Meta { fee_payer: None, fee_token, nonce: None },
                        revoke_keys: vec![],
                        pre_calls: vec![],
                        pre_call: false,
                    },
                    state_overrides: Default::default(),
                    balance_overrides: Default::default(),
                    key: Some(self.key.to_call_key()),
                })
                .await
            {
                Ok(response) => response,
                Err(err) => {
                    retries -= 1;
                    if retries == 0 {
                        return Err(err).context("prepare calls failed");
                    } else {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                }
            };

            retries = 5;

            // It might happen that we've received a preconfirmation for previous transaction but
            // Relay is not yet at the latest state. For this case we need to make sure that our new
            // intent does not have the same nonce and otherwise retry a bit later.
            // todo(onbjerg): this only works for single chain intents right now
            for quote in context.quote().unwrap().ty().quotes.iter() {
                let nonce = quote.intent.nonce;
                if previous_nonce == Some(nonce) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                } else {
                    previous_nonce = Some(nonce);
                }
            }

            let signature =
                self.key.sign_payload_hash(digest).await.expect("failed to sign bundle digest");

            info!(
                %digest,
                account = %self.address,
                total_elapsed = ?prepare_start.elapsed(),
                elapsed = ?prepare_start.elapsed(),
                "Prepared bundle"
            );
            let send_start = Instant::now();
            let bundle_id = relay_client
                .send_prepared_calls(relay::types::rpc::SendPreparedCallsParameters {
                    capabilities: Default::default(),
                    context,
                    key: self.key.to_call_key(),
                    signature,
                })
                .await
                .expect("send prepared calls failed");
            info!(
                %digest,
                account = %self.address,
                bundle_id = %bundle_id.id,
                total_elapsed = ?prepare_start.elapsed(),
                elapsed = ?send_start.elapsed(),
                "Sent bundle"
            );
            loop {
                let status = relay_client.get_calls_status(bundle_id.id).await;
                trace!("got bundle status: {:?}", status);
                if status.is_ok_and(|status| status.status.is_final()) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }

            info!(
                %digest,
                account = %self.address,
                bundle_id = %bundle_id.id,
                total_elapsed = ?prepare_start.elapsed(),
                "Bundle confirmed"
            );
        }
    }
}

struct StressTester {
    relay_client: HttpClient,
    args: Args,
    accounts: Vec<StressAccount>,
}

impl StressTester {
    async fn new(args: Args) -> eyre::Result<Self> {
        let relay_client = HttpClientBuilder::new().build(
            &args
                .rpc_urls
                .first()
                .ok_or_else(|| eyre::eyre!("at least one rpc url must be specified"))?,
        )?;
        let signer = DynSigner::from_signing_key(&args.private_key).await?;
        let version = relay_client.health().await?;
        info!("Connected to relay at {}, version {}", &args.rpc_urls.first().unwrap(), version);

        let caps = relay_client.get_capabilities(vec![args.chain_id.id()]).await?;

        let supports_fee_token = caps.chain(args.chain_id.id()).has_token(&args.fee_token);

        if !supports_fee_token {
            eyre::bail!("fee token {} is not supported on chain {}", args.fee_token, args.chain_id);
        }

        info!("Initializing {} accounts", args.accounts);
        let accounts = futures_util::future::try_join_all((0..args.accounts).map(|acc_number| {
            let relay_client = relay_client.clone();
            let acc_target = args.accounts;
            let caps = caps.clone();
            async move {
                let eoa = DynSigner::from_signing_key(&B256::random().to_string()).await?;
                let key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?
                    .expect("failed to create key for account");
                let PrepareUpgradeAccountResponse { context, digests, .. } = relay_client
                    .prepare_upgrade_account(PrepareUpgradeAccountParameters {
                        capabilities: UpgradeAccountCapabilities {
                            authorize_keys: vec![key.to_authorized()],
                        },
                        chain_id: Some(args.chain_id.id()),
                        address: eoa.address(),
                        delegation: caps
                            .chain(args.chain_id.id())
                            .contracts
                            .delegation_proxy
                            .address,
                    })
                    .await
                    .wrap_err("failed to prepare create account")?;

                let address = eoa.address();
                relay_client
                    .upgrade_account(UpgradeAccountParameters {
                        context,
                        signatures: UpgradeAccountSignatures {
                            auth: eoa.sign_hash(&digests.auth).await?,
                            exec: eoa.sign_hash(&digests.exec).await?,
                        },
                    })
                    .await
                    .wrap_err("failed to create account")?;
                info!(account = %address, "#{}/{} Account initialized", acc_number, acc_target);

                Ok::<_, eyre::Error>(StressAccount::new(address, key))
            }
        }))
        .await?;
        info!("Initialized {} accounts", args.accounts);

        let disperse_address = CREATE2_DEPLOYER.create2(B256::ZERO, keccak256(&Disperse::BYTECODE));

        let mut providers = Vec::new();
        for rpc_url in &args.rpc_urls {
            let provider = ProviderBuilder::new()
                .disable_recommended_fillers()
                .filler(NonceFiller::new(CachedNonceManager::default()))
                .filler(GasFiller)
                .filler(ChainIdFiller::new(Some(args.chain_id.id())))
                .wallet(EthereumWallet::from(signer.0.clone()))
                .connect(rpc_url.as_str())
                .await?
                .erased();

            providers.push(provider);
        }

        try_join_all(providers.iter().map(|provider| {
            let accounts = accounts.clone();
            let signer = signer.clone();
            async move {
                if provider.get_code_at(disperse_address).await?.is_empty() {
                    info!("Deploying Disperse contract");
                    let receipt: alloy::rpc::types::TransactionReceipt = provider
                        .send_transaction(
                            TransactionRequest::default().to(CREATE2_DEPLOYER).input(
                                (B256::ZERO, &Disperse::BYTECODE).abi_encode_packed().into(),
                            ),
                        )
                        .await?
                        .get_receipt()
                        .await?;
                    assert!(receipt.status());
                    info!("Deployed Disperse contract");
                }

                let disperse = Disperse::new(disperse_address, &provider);

                let fee_token = IERC20Instance::new(args.fee_token, &provider);
                if fee_token.allowance(signer.address(), disperse_address).call().await?
                    < args.fee_token_amount * U256::from(accounts.len())
                {
                    info!("Approving Disperse contract");
                    fee_token
                        .approve(disperse_address, U256::MAX)
                        .send()
                        .await?
                        .get_receipt()
                        .await?;
                    info!("Approved Disperse contract");
                }

                let mut funded = 0;
                for batch in accounts.chunks(50) {
                    info!(
                        "Funding accounts #{}..{}/{} ",
                        funded,
                        funded + batch.len(),
                        accounts.len()
                    );

                    disperse
                        .disperseToken(
                            args.fee_token,
                            batch.iter().map(|acc| acc.address).collect(),
                            std::iter::repeat_n(args.fee_token_amount, batch.len()).collect(),
                        )
                        .send()
                        .await?
                        .get_receipt()
                        .await?;

                    info!(
                        "Funded accounts #{}..{}/{} ",
                        funded,
                        funded + batch.len(),
                        accounts.len()
                    );
                    funded += batch.len();
                }

                Ok::<_, eyre::Error>(())
            }
        }))
        .await?;

        Ok(Self { relay_client, args, accounts })
    }

    async fn spawn(self) -> eyre::Result<()> {
        let tester = self;
        tokio::spawn(async move { tester.run().await }).await?
    }

    async fn run(self) -> eyre::Result<()> {
        info!("Starting stress test");

        let mut tasks = FuturesUnordered::new();
        for account in self.accounts.into_iter() {
            let client = self.relay_client.clone();
            tasks.push(tokio::spawn(async move {
                account.run(self.args.chain_id.id(), self.args.fee_token, client).await
            }));
        }

        while let Some(finished) = tasks.next().await {
            match finished {
                Ok(_) => info!("An account finished stress test"),
                Err(err) => error!("an account failed stress test: {}", err),
            }
        }

        info!("Stress test ended");
        Ok(())
    }
}

#[derive(Debug, Parser)]
#[command(author, about = "Relay stress tester", long_about = None)]
struct Args {
    /// RPC URL of the chain we are testing on.
    #[arg(long = "rpc-url", value_name = "RPC_URL", required = true)]
    rpc_urls: Vec<Url>,
    /// Chain ID of the chain to test on.
    #[arg(long = "chain-id", value_name = "CHAIN_ID", required = true)]
    chain_id: Chain,
    /// Private key of the account to use for testing.
    ///
    /// This account should have sufficient fee tokens to cover the gas costs of the intents.
    #[arg(long = "private-key", value_name = "PRIVATE_KEY", required = true, env = "PK")]
    private_key: String,
    /// Address of the fee token to use for testing.
    #[arg(long = "fee-token", value_name = "ADDRESS", required = true)]
    fee_token: Address,
    /// Amount of fee tokens to fund each account with in wei.
    #[arg(long = "fee-token-amount", value_name = "AMOUNT", default_value_t = U256::from(1000000000000000000u128))]
    fee_token_amount: U256,
    /// Number of accounts to create and test with.
    #[arg(long = "accounts", value_name = "COUNT", default_value_t = 1000)]
    accounts: usize,
}

impl Args {
    async fn run(self) -> eyre::Result<()> {
        let tester = StressTester::new(self).await?;

        tester.spawn().await
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder().with_default_directive(LevelFilter::INFO.into()).from_env_lossy(),
        )
        .init();

    let args = Args::parse();
    if let Err(err) = args.run().await {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
