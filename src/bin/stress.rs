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
use tokio::time::Instant;
use tracing::{error, info, level_filters::LevelFilter, trace};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};
use url::Url;

alloy::sol! {
    interface IERC20 {
        function balanceOf(address account) external view returns (uint256);
        function allowance(address owner, address spender) external view returns (uint256);
        function transferFrom(address from, address to, uint256 amount) external;
    }

    #[sol(rpc, bytecode = "0x6080604052348015600e575f5ffd5b506106e08061001c5f395ff3fe608060405234801561000f575f5ffd5b5060043610610029575f3560e01c8063d8cd5ed41461002d575b5f5ffd5b61004760048036038101906100429190610397565b610049565b005b83839050816100589190610435565b8273ffffffffffffffffffffffffffffffffffffffff166370a08231336040518263ffffffff1660e01b81526004016100919190610485565b602060405180830381865afa1580156100ac573d5f5f3e3d5ffd5b505050506040513d601f19601f820116820180604052508101906100d091906104b2565b1015610111576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161010890610537565b60405180910390fd5b83839050816101209190610435565b8273ffffffffffffffffffffffffffffffffffffffff1663dd62ed3e33306040518363ffffffff1660e01b815260040161015b929190610555565b602060405180830381865afa158015610176573d5f5f3e3d5ffd5b505050506040513d601f19601f8201168201806040525081019061019a91906104b2565b10156101db576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016101d2906105c6565b60405180910390fd5b5f5f90505b84849050811015610289578273ffffffffffffffffffffffffffffffffffffffff166323b872dd3387878581811061021b5761021a6105e4565b5b9050602002016020810190610230919061063b565b856040518463ffffffff1660e01b815260040161024f93929190610675565b5f604051808303815f87803b158015610266575f5ffd5b505af1158015610278573d5f5f3e3d5ffd5b5050505080806001019150506101e0565b5050505050565b5f5ffd5b5f5ffd5b5f5ffd5b5f5ffd5b5f5ffd5b5f5f83601f8401126102b9576102b8610298565b5b8235905067ffffffffffffffff8111156102d6576102d561029c565b5b6020830191508360208202830111156102f2576102f16102a0565b5b9250929050565b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f610322826102f9565b9050919050565b5f61033382610318565b9050919050565b61034381610329565b811461034d575f5ffd5b50565b5f8135905061035e8161033a565b92915050565b5f819050919050565b61037681610364565b8114610380575f5ffd5b50565b5f813590506103918161036d565b92915050565b5f5f5f5f606085870312156103af576103ae610290565b5b5f85013567ffffffffffffffff8111156103cc576103cb610294565b5b6103d8878288016102a4565b945094505060206103eb87828801610350565b92505060406103fc87828801610383565b91505092959194509250565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f61043f82610364565b915061044a83610364565b925082820261045881610364565b9150828204841483151761046f5761046e610408565b5b5092915050565b61047f81610318565b82525050565b5f6020820190506104985f830184610476565b92915050565b5f815190506104ac8161036d565b92915050565b5f602082840312156104c7576104c6610290565b5b5f6104d48482850161049e565b91505092915050565b5f82825260208201905092915050565b7f496e73756666696369656e742062616c616e63650000000000000000000000005f82015250565b5f6105216014836104dd565b915061052c826104ed565b602082019050919050565b5f6020820190508181035f83015261054e81610515565b9050919050565b5f6040820190506105685f830185610476565b6105756020830184610476565b9392505050565b7f496e73756666696369656e7420616c6c6f77616e6365000000000000000000005f82015250565b5f6105b06016836104dd565b91506105bb8261057c565b602082019050919050565b5f6020820190508181035f8301526105dd816105a4565b9050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52603260045260245ffd5b61061a81610318565b8114610624575f5ffd5b50565b5f8135905061063581610611565b92915050565b5f602082840312156106505761064f610290565b5b5f61065d84828501610627565b91505092915050565b61066f81610364565b82525050565b5f6060820190506106885f830186610476565b6106956020830185610476565b6106a26040830184610666565b94935050505056fea2646970667358221220a9b0e9977b932989569695c2c35e1b737afff53c3371b2d3a13337e354a8a60e64736f6c634300081c0033")]
    contract Funder {
        function fund(address[] calldata accounts, IERC20 token, uint256 amount) external {
            require(token.balanceOf(msg.sender) >= amount * accounts.length, "Insufficient balance");
            require(token.allowance(msg.sender, address(this)) >= amount * accounts.length, "Insufficient allowance");

            for (uint256 i = 0; i < accounts.length; i++) {
                token.transferFrom(msg.sender, accounts[i], amount);
            }
        }
    }
}

const CREATE2_DEPLOYER: Address = address!("0x4e59b44847b379578588920cA78FbF26c0B4956C");

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
            .wallet(EthereumWallet::from(signer.0.clone()))
            .connect_http(args.rpc_url.clone())
            .erased();

        let health = relay_client.health().await?;
        info!("Connected to relay at {}, version {}", &args.relay_url, health.version);

        let supports_fee_token =
            relay_client.fee_tokens().await?.contains(args.chain_id.id(), &args.fee_token);
        if !supports_fee_token {
            eyre::bail!("fee token {} is not supported on chain {}", args.fee_token, args.chain_id);
        }

        info!("Initializing {} accounts", args.accounts);
        let accounts = futures_util::future::try_join_all((0..args.accounts).map(|acc_number| {
            let relay_client = relay_client.clone();
            let acc_target = args.accounts;
            async move {
                let key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?
                    .expect("failed to create key for account");
                let PrepareCreateAccountResponse { capabilities: _, digests: _, context, address } =
                    relay_client
                        .prepare_create_account(PrepareCreateAccountParameters {
                            capabilities: PrepareCreateAccountCapabilities {
                                authorize_keys: vec![key.to_authorized(None).await?],
                                delegation: health.delegation_proxy,
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

                Ok::<_, eyre::Error>(StressAccount::new(address, key))
            }
        }))
        .await?;
        info!("Initialized {} accounts", args.accounts);

        let funder_address = CREATE2_DEPLOYER.create2(B256::ZERO, keccak256(&Funder::BYTECODE));

        if provider.get_code_at(funder_address).await?.is_empty() {
            info!("Deploying funder contract");
            let receipt = provider
                .send_transaction(
                    TransactionRequest::default()
                        .to(CREATE2_DEPLOYER)
                        .input((B256::ZERO, &Funder::BYTECODE).abi_encode_packed().into()),
                )
                .await?
                .get_receipt()
                .await?;
            assert!(receipt.status());
            info!("Deployed funder contract");
        }

        let funder = Funder::new(funder_address, &provider);

        let fee_token = IERC20Instance::new(args.fee_token, &provider);
        if fee_token.allowance(signer.address(), funder_address).call().await?
            < args.fee_token_amount * U256::from(accounts.len())
        {
            info!("Approving funder contract");
            fee_token.approve(funder_address, U256::MAX).send().await?.get_receipt().await?;
            info!("Approved funder contract");
        }

        let mut funded = 0;
        for batch in accounts.chunks(50) {
            info!("Funding accounts #{}..{}/{} ", funded, funded + batch.len(), accounts.len());

            funder
                .fund(
                    batch.iter().map(|acc| acc.address).collect(),
                    args.fee_token,
                    args.fee_token_amount,
                )
                .send()
                .await?
                .get_receipt()
                .await?;

            info!("Funded accounts #{}..{}/{} ", funded, funded + batch.len(), accounts.len());
            funded += batch.len();
        }

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
