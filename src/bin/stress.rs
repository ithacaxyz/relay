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

use std::{sync::Arc, time::Duration};

use alloy::{
    network::EthereumWallet,
    primitives::{Address, ChainId, U256, bytes},
    providers::{
        Provider, ProviderBuilder,
        fillers::{CachedNonceManager, ChainIdFiller, GasFiller, NonceFiller},
    },
};
use alloy_chains::Chain;
use clap::Parser;
use eyre::Context;
use futures_util::{StreamExt, stream::FuturesUnordered};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use relay::{
    rpc::RelayApiClient,
    signers::{DynSigner, Eip712PayLoadSigner},
    types::{
        Call,
        IERC20::IERC20Instance,
        KeyType, KeyWith712Signer,
        rpc::{
            CreateAccountParameters, KeySignature, Meta, PrepareCallsCapabilities,
            PrepareCallsParameters, PrepareCallsResponse, PrepareCreateAccountCapabilities,
            PrepareCreateAccountParameters, PrepareCreateAccountResponse,
        },
    },
};
use tokio::{sync::Semaphore, time::Instant};
use tracing::{error, info, level_filters::LevelFilter, trace};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};
use url::Url;

#[derive(Debug)]
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
        loop {
            let prepare_start = Instant::now();
            let PrepareCallsResponse { context, digest, .. } = relay_client
                .prepare_calls(PrepareCallsParameters {
                    calls: vec![Call { to: Address::ZERO, value: U256::ZERO, data: bytes!("") }],
                    chain_id,
                    from: self.address,
                    capabilities: PrepareCallsCapabilities {
                        authorize_keys: vec![],
                        meta: Meta { fee_token, key_hash: self.key.key_hash(), nonce: None },
                        revoke_keys: vec![],
                        pre_ops: vec![],
                        pre_op: false,
                    },
                })
                .await
                .expect("prepare calls failed");
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
                    context,
                    signature: KeySignature {
                        public_key: self.key.publicKey.clone(),
                        key_type: self.key.keyType,
                        value: signature,
                        prehash: false,
                    },
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
        let relay_client = HttpClientBuilder::new().build(&args.relay_url)?;
        let signer = DynSigner::load(&args.private_key, None).await?;
        let provider = ProviderBuilder::new()
            .disable_recommended_fillers()
            .filler(NonceFiller::new(CachedNonceManager::default()))
            .filler(GasFiller)
            .filler(ChainIdFiller::new(Some(args.chain_id.id())))
            .wallet(EthereumWallet::from(signer.0))
            .on_http(args.rpc_url.clone())
            .erased();

        info!(
            "Connected to relay at {}, version {}",
            &args.relay_url,
            relay_client.health().await?.version
        );

        let supports_fee_token =
            relay_client.fee_tokens().await?.contains(args.chain_id.id(), &args.fee_token);
        if !supports_fee_token {
            eyre::bail!("fee token {} is not supported on chain {}", args.fee_token, args.chain_id);
        }

        info!("Initializing {} accounts", args.accounts);
        let sema = Arc::new(Semaphore::new(10));
        let accounts = futures_util::future::try_join_all((0..args.accounts).map(|acc_number| {
            let relay_client = relay_client.clone();
            let sema = sema.clone();
            let provider = provider.clone();
            let acc_target = args.accounts;
            async move {
                let key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?
                    .expect("failed to create key for account");
                let PrepareCreateAccountResponse { capabilities: _, digests: _, context, address } =
                    relay_client
                        .prepare_create_account(PrepareCreateAccountParameters {
                            capabilities: PrepareCreateAccountCapabilities {
                                authorize_keys: vec![key.to_authorized(None).await?],
                                delegation: args.delegation,
                            },
                            chain_id: args.chain_id.id(),
                        })
                        .await
                        .wrap_err("failed to prepare create account")?;

                relay_client
                    .create_account(CreateAccountParameters {
                        context,
                        signatures: vec![KeySignature {
                            public_key: key.publicKey.clone(),
                            key_type: key.keyType,
                            value: key.id_sign(address).await?.as_bytes().into(),
                            prehash: false,
                        }],
                    })
                    .await
                    .wrap_err("failed to create account")?;
                info!(account = %address, "#{}/{} Account initialized", acc_number, acc_target);

                let permit = sema.acquire().await.wrap_err("semaphore closed")?;
                info!(account = %address, "#{}/{} Funding account", acc_number, acc_target);
                IERC20Instance::new(args.fee_token, &provider)
                    .transfer(address, args.fee_token_amount)
                    .send()
                    .await
                    .wrap_err("funding account failed")?
                    .get_receipt()
                    .await
                    .wrap_err("failed to get receipt for account funding")?;
                info!(account = %address, "#{}/{} Account funded", acc_number, acc_target);
                drop(permit);

                Ok::<_, eyre::Error>(StressAccount::new(address, key))
            }
        }))
        .await?;
        info!("Initialized {} accounts", args.accounts);

        Ok(Self { relay_client, args, accounts })
    }

    async fn spawn(self) -> eyre::Result<()> {
        let tester = self;
        tokio::spawn(async move { tester.run().await }).await?
    }

    async fn run(self) -> eyre::Result<()> {
        info!("Starting stress test");

        // we use a semaphore to limit the number of concurrent funding transactions, since mempools
        // have limits per account, and sending too many might cause txs to get
        // dropped/rejected/stuck
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
    /// Relay URL to connect to.
    #[arg(long = "relay-url", value_name = "RELAY_URL", required = true)]
    relay_url: String,
    /// RPC URL of the chain we are testing on.
    #[arg(long = "rpc-url", value_name = "RPC_URL", required = true)]
    rpc_url: Url,
    /// Chain ID of the chain to test on.
    #[arg(long = "chain-id", value_name = "CHAIN_ID", required = true)]
    chain_id: Chain,
    /// Private key of the account to use for testing.
    ///
    /// This account should have sufficient fee tokens to cover the gas costs of the userops.
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
    /// Address of the delegation contract to use for testing.
    #[arg(long = "delegation", value_name = "ADDRESS", required = true)]
    delegation: Address,
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
