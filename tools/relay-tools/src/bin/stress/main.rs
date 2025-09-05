//! Relay stress testing tool.
//!
//! # Example
//!
//! ```sh
//! cargo r --bin stress -- \
//!     --relay-url https://relay-staging.ithaca.xyz \
//!     --rpc-url https://rpc1.example.com \
//!     --rpc-url https://rpc2.example.com \
//!     --private-key $PRIVATE_KEY \
//!     --fee-token 0x541a5505620A658932e326D0dC996C460f5AcBE1 \
//!     --accounts 500
//! ```
//! The test script will transfer the fee token out of the account specified in --private-key, so it
//! must have enough balance to cover for the accounts. The amount sent to each account is
//! configurable
// it will first create all the accounts and fund them - might take a while.

use alloy::{
    consensus::constants::ETH_TO_WEI,
    network::EthereumWallet,
    primitives::{Address, B256, ChainId, U64, U256, address, keccak256},
    providers::{
        DynProvider, Provider, ProviderBuilder,
        fillers::{CachedNonceManager, ChainIdFiller, GasFiller, NonceFiller},
    },
    rpc::types::TransactionRequest,
    sol_types::SolValue,
    transports::TransportResult,
};
use clap::Parser;
use eyre::Context;
use futures::FutureExt;
use futures_util::{StreamExt, future::try_join_all, stream::FuturesUnordered};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use relay::{
    rpc::RelayApiClient,
    signers::{DynSigner, Eip712PayLoadSigner},
    storage::BundleStatus,
    types::{
        Call,
        IERC20::IERC20Instance,
        KeyType, KeyWith712Signer,
        rpc::{
            BundleId, CallsStatus, Meta, PrepareCallsCapabilities, PrepareCallsParameters,
            PrepareCallsResponse, PrepareUpgradeAccountParameters, PrepareUpgradeAccountResponse,
            RelayCapabilities, RequiredAsset, SendPreparedCallsParameters,
            UpgradeAccountCapabilities, UpgradeAccountParameters, UpgradeAccountSignatures,
        },
    },
};
use relay_tools::common::{format_prepare_debug, init_logging, wait_for_calls_status};
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{sync::mpsc, time::Instant};
use tracing::{debug, error, info, instrument, warn};
use url::Url;

alloy::sol! {
    /// <https://github.com/omniaprotocol/disperse.app/blob/main/Disperse.sol>
    /// Bytecode from <https://basescan.org/tx/0x6183b11e486313c20c8f8421b858fba9b2af089963b0e52d2485bf0ca7471fb5>
    #[sol(rpc, bytecode = "0x608060405234801561001057600080fd5b506106f4806100206000396000f300608060405260043610610057576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806351ba162c1461005c578063c73a2d60146100cf578063e63d38ed14610142575b600080fd5b34801561006857600080fd5b506100cd600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803590602001908201803590602001919091929391929390803590602001908201803590602001919091929391929390505050610188565b005b3480156100db57600080fd5b50610140600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803590602001908201803590602001919091929391929390803590602001908201803590602001919091929391929390505050610309565b005b6101866004803603810190808035906020019082018035906020019190919293919293908035906020019082018035906020019190919293919293905050506105b0565b005b60008090505b84849050811015610301578573ffffffffffffffffffffffffffffffffffffffff166323b872dd3387878581811015156101c457fe5b9050602002013573ffffffffffffffffffffffffffffffffffffffff1686868681811015156101ef57fe5b905060200201356040518463ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018281526020019350505050602060405180830381600087803b1580156102ae57600080fd5b505af11580156102c2573d6000803e3d6000fd5b505050506040513d60208110156102d857600080fd5b810190808051906020019092919050505015156102f457600080fd5b808060010191505061018e565b505050505050565b60008060009150600090505b8585905081101561034657838382818110151561032e57fe5b90506020020135820191508080600101915050610315565b8673ffffffffffffffffffffffffffffffffffffffff166323b872dd3330856040518463ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018281526020019350505050602060405180830381600087803b15801561041d57600080fd5b505af1158015610431573d6000803e3d6000fd5b505050506040513d602081101561044757600080fd5b8101908080519060200190929190505050151561046357600080fd5b600090505b858590508110156105a7578673ffffffffffffffffffffffffffffffffffffffff1663a9059cbb878784818110151561049d57fe5b9050602002013573ffffffffffffffffffffffffffffffffffffffff1686868581811015156104c857fe5b905060200201356040518363ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200182815260200192505050602060405180830381600087803b15801561055457600080fd5b505af1158015610568573d6000803e3d6000fd5b505050506040513d602081101561057e57600080fd5b8101908080519060200190929190505050151561059a57600080fd5b8080600101915050610468565b50505050505050565b600080600091505b858590508210156106555785858381811015156105d157fe5b9050602002013573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166108fc858585818110151561061557fe5b905060200201359081150290604051600060405180830381858888f19350505050158015610647573d6000803e3d6000fd5b5081806001019250506105b8565b3073ffffffffffffffffffffffffffffffffffffffff1631905060008111156106c0573373ffffffffffffffffffffffffffffffffffffffff166108fc829081150290604051600060405180830381858888f193505050501580156106be573d6000803e3d6000fd5b505b5050505050505600a165627a7a723058204f25a733917e0bf639cd1e101d55bd927f843fb395fb2a963a7909c09ae023ed0029")]
    contract Disperse {
        function disperseEther(address[] recipients, uint256[] values) external payable;
        function disperseToken(address token, address[] recipients, uint256[] values) external;
    }
}

const CREATE2_DEPLOYER: Address = address!("0x4e59b44847b379578588920cA78FbF26c0B4956C");

#[derive(Debug, Clone)]
struct PendingSettlement {
    bundle_id: BundleId,
    input_chains: Vec<ChainId>,
    chain_id: ChainId,
    tx: mpsc::UnboundedSender<PendingSettlement>,
}

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
    #[expect(clippy::too_many_arguments)]
    async fn run(
        self,
        chain_id: ChainId,
        fee_token: Address,
        relay_client: HttpClient,
        recipient: Address,
        transfer_amount: U256,
        settlement_tx: mpsc::UnboundedSender<PendingSettlement>,
        failed_counter: Arc<AtomicUsize>,
    ) -> eyre::Result<()> {
        let mut retries = 5;
        loop {
            let prepare_start = Instant::now();
            debug!(
                account = %self.address,
                total_elapsed = ?prepare_start.elapsed(),
                retries,
                "Preparing bundle",
            );
            let call = if !fee_token.is_zero() {
                Call::transfer(fee_token, recipient, transfer_amount)
            } else {
                Call { to: recipient, value: transfer_amount, data: Default::default() }
            };
            let prepare_params = PrepareCallsParameters {
                calls: vec![call],
                chain_id,
                from: Some(self.address),
                capabilities: PrepareCallsCapabilities {
                    authorize_keys: vec![],
                    meta: Meta { fee_payer: None, fee_token: Some(fee_token), nonce: None },
                    revoke_keys: vec![],
                    pre_calls: vec![],
                    pre_call: false,
                    required_funds: vec![RequiredAsset::new(fee_token, transfer_amount)],
                },
                state_overrides: Default::default(),
                balance_overrides: Default::default(),
                key: Some(self.key.to_call_key()),
            };
            let PrepareCallsResponse { context, digest, .. } =
                match relay_client.prepare_calls(prepare_params.clone()).await {
                    Ok(response) => response,
                    Err(err) => {
                        eprint!(
                            "{}",
                            format_prepare_debug(
                                &prepare_params,
                                None,
                                Some("See error details above")
                            )
                        );
                        warn!(
                            account = %self.address,
                            total_elapsed = ?prepare_start.elapsed(),
                            retries,
                            ?err,
                            "Prepare calls failed",
                        );
                        retries -= 1;
                        if retries == 0 {
                            return Err(err).context("prepare calls failed");
                        } else {
                            tokio::time::sleep(Duration::from_millis(500)).await;
                            continue;
                        }
                    }
                };

            retries = 5;

            // If all quotes have a fee token deficit then the stress test ends.
            if context.quote().unwrap().ty().quotes.iter().all(|q| !q.fee_token_deficit.is_zero()) {
                warn!("Fee token deficit on all chains.");
                return Ok(());
            }

            let signature =
                self.key.sign_payload_hash(digest).await.expect("failed to sign bundle digest");
            let chain_ids: Vec<_> =
                context.quote().unwrap().ty().quotes.iter().map(|quote| quote.chain_id).collect();
            let inputs =
                if chain_ids.len() == 1 { &chain_ids } else { &chain_ids[0..chain_ids.len() - 1] }
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
            info!(
                %digest,
                account = %self.address,
                total_elapsed = ?prepare_start.elapsed(),
                elapsed = ?prepare_start.elapsed(),
                "Prepared bundle ({} -> {})",
                inputs, chain_id
            );
            let send_start = Instant::now();
            let bundle_id = relay_client
                .send_prepared_calls(SendPreparedCallsParameters {
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
                "Sent bundle ({} -> {})",
                inputs, chain_id
            );
            let status = wait_for_calls_status(&relay_client, bundle_id.id).await.unwrap();

            if chain_ids.len() > 1 {
                check_settlement_status(
                    PendingSettlement {
                        bundle_id: bundle_id.id,
                        input_chains: chain_ids[..chain_ids.len() - 1].to_vec(),
                        chain_id,
                        tx: settlement_tx.clone(),
                    },
                    &status,
                    &failed_counter,
                )
                .await;
            }

            if status.status.is_confirmed() {
                info!(
                    %digest,
                    account = %self.address,
                    bundle_id = %bundle_id.id,
                    total_elapsed = ?prepare_start.elapsed(),
                    "Bundle confirmed ({} -> {})",
                    inputs, chain_id
                );
            } else {
                error!(
                    %digest,
                    account = %self.address,
                    bundle_id = %bundle_id.id,
                    total_elapsed = ?prepare_start.elapsed(),
                    "Bundle failed ({} -> {})",
                    inputs, chain_id
                );
                return Err(eyre::eyre!("bundle failed: {:#?}", status.receipts));
            }
        }
    }
}

struct StressTester {
    relay_client: HttpClient,
    args: Args,
    accounts: Vec<StressAccount>,
    destination_chain_id: ChainId,
    signer: DynSigner,
    fee_token_map: Arc<HashMap<ChainId, Address>>,
}

impl StressTester {
    async fn new(args: Args) -> eyre::Result<Self> {
        let relay_client = HttpClientBuilder::new().build(&args.relay_url)?;
        let signer = DynSigner::from_signing_key(&args.private_key).await?;
        let health = relay_client.health().await?;
        info!("Connected to relay at {}, version {}", &args.relay_url, health.version);

        // Initialize providers
        let source_providers = try_join_all(
            args.src_rpc
                .clone()
                .into_iter()
                .map(|rpc_url| create_provider(rpc_url, signer.clone())),
        )
        .await?;
        let destination_provider = create_provider(args.dst_rpc.clone(), signer.clone()).await?;

        // Gather chain IDs
        let source_chain_ids =
            try_join_all(source_providers.iter().map(Provider::get_chain_id)).await?;
        let destination_chain_id = destination_provider.get_chain_id().await?;
        let chain_ids = source_chain_ids
            .iter()
            .chain(std::iter::once(&destination_chain_id))
            .copied()
            .collect::<Vec<_>>();
        info!("Destination chain is {destination_chain_id}");

        // Get capabilities for all chains
        let caps = relay_client
            .get_capabilities(Some(chain_ids.iter().map(|&id| U64::from(id)).collect()))
            .await?;

        // Build fee token mapping across all chains
        let fee_token_map = build_fee_token_map(&caps, &chain_ids, args.fee_token).await?;

        // Initialize accounts on destination chain
        info!("Initializing {} accounts", args.accounts);
        let accounts = try_join_all((0..args.accounts).map(|acc_number| {
            let relay_client = relay_client.clone();
            let acc_target = args.accounts;
            let caps = caps.clone();
            async move {
                let eoa_key = B256::random();
                let eoa = DynSigner::from_signing_key(&eoa_key.to_string()).await?;
                info!("Created EOA account: key={eoa_key:?} address={}", eoa.address());
                let key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?
                    .expect("failed to create key for account");
                let PrepareUpgradeAccountResponse { context, digests, .. } = relay_client
                    .prepare_upgrade_account(PrepareUpgradeAccountParameters {
                        capabilities: UpgradeAccountCapabilities {
                            authorize_keys: vec![key.to_authorized()],
                        },
                        chain_id: Some(destination_chain_id),
                        address: eoa.address(),
                        delegation: caps
                            .chain(destination_chain_id)
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

        let chains_to_fund = if source_chain_ids.is_empty() {
            // If we only have a single chain, fund it.
            vec![(&destination_provider, destination_chain_id)]
        } else {
            // If we're testing interop, only fund the source chains.
            source_providers.iter().zip(source_chain_ids).collect()
        };

        // Deploy contracts if needed and fund accounts on all chains
        try_join_all(chains_to_fund.into_iter().map(|(provider, chain_id)| {
            fund_accounts(
                provider,
                accounts.clone(),
                signer.clone(),
                fee_token_map.clone(),
                args.fee_token_amount,
                disperse_address,
            )
            .map(move |result| {
                result.wrap_err_with(|| format!("failed to fund accounts on chain {chain_id}"))
            })
        }))
        .await?;

        Ok(Self { destination_chain_id, relay_client, args, accounts, signer, fee_token_map })
    }

    async fn spawn(self) -> eyre::Result<()> {
        let tester = self;
        tokio::spawn(async move { tester.run().await }).await?
    }

    async fn run(self) -> eyre::Result<()> {
        info!("Starting stress test");

        let failed_settlements_counter = Arc::new(AtomicUsize::new(0));
        let (settlement_tx, settlement_rx) = mpsc::unbounded_channel::<PendingSettlement>();

        // Spawn settlement tracker worker thread
        let worker_client = self.relay_client.clone();
        let worker_counter = failed_settlements_counter.clone();
        let worker_handle = tokio::spawn(async move {
            settlement_worker(worker_client, settlement_rx, worker_counter).await
        });

        let mut tasks = FuturesUnordered::new();
        let recipient = self.signer.address();
        let destination_fee_token =
            self.fee_token_map.get(&self.destination_chain_id).ok_or_else(|| {
                eyre::eyre!(
                    "no fee token mapping for destination chain {}",
                    self.destination_chain_id
                )
            })?;

        for account in self.accounts.into_iter() {
            let client = self.relay_client.clone();
            let tx = settlement_tx.clone();
            let counter = failed_settlements_counter.clone();
            let destination_fee_token = *destination_fee_token;
            tasks.push(tokio::spawn(async move {
                account
                    .run(
                        self.destination_chain_id,
                        destination_fee_token,
                        client,
                        recipient,
                        self.args.transfer_amount,
                        tx,
                        counter,
                    )
                    .await
            }));
        }

        while let Some(finished) = tasks.next().await {
            match finished {
                Ok(Ok(())) => info!("An account finished stress test."),
                Ok(Err(err)) => error!("An account failed stress test: {}", err),
                Err(err) => error!("An account failed stress test: {}", err),
            }
        }

        // close the channel to signal worker to finish
        drop(settlement_tx);
        worker_handle.await?;

        let failed_count = failed_settlements_counter.load(Ordering::SeqCst);
        if failed_count > 0 {
            error!("Stress test failed with {} failed settlements", failed_count);
        }

        info!("Stress test ended");
        Ok(())
    }
}

async fn create_provider(rpc_url: Url, signer: DynSigner) -> TransportResult<DynProvider> {
    Ok(ProviderBuilder::new()
        .disable_recommended_fillers()
        .filler(NonceFiller::new(CachedNonceManager::default()))
        .filler(GasFiller)
        .filler(ChainIdFiller::new(None))
        .wallet(EthereumWallet::from(signer.0))
        .connect(rpc_url.as_str())
        .await?
        .erased())
}

/// Checks the settlement status of an interop bundle and handles it accordingly:
/// - Done: logs success
/// - Failed: logs error and increments failure counter
/// - Pending: re-queues the settlement for later checking
async fn check_settlement_status(
    settlement: PendingSettlement,
    status: &CallsStatus,
    failed_counter: &Arc<AtomicUsize>,
) {
    let Some(interop_status) = status.capabilities.as_ref().and_then(|c| c.interop_status) else {
        error!(bundle_id = %settlement.bundle_id, "Missing interop status");
        failed_counter.fetch_add(1, Ordering::SeqCst);
        return;
    };

    let inputs =
        || settlement.input_chains.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ");

    match interop_status {
        BundleStatus::Done => {
            info!(
                bundle_id = %settlement.bundle_id,
                "Interop settled ({} -> {})",
                inputs(), settlement.chain_id
            );
        }
        BundleStatus::Failed => {
            error!(
                bundle_id = %settlement.bundle_id,
                "Interop settlement failed ({} -> {})",
                inputs(), settlement.chain_id
            );
            failed_counter.fetch_add(1, Ordering::SeqCst);
        }
        _ => {
            // Still pending, add to queue for later checking
            let _ = settlement.tx.clone().send(settlement);
        }
    }
}

async fn settlement_worker(
    client: HttpClient,
    mut rx: mpsc::UnboundedReceiver<PendingSettlement>,
    failed_counter: Arc<AtomicUsize>,
) {
    while let Some(settlement) = rx.recv().await {
        tokio::time::sleep(Duration::from_millis(20)).await;

        let Ok(status) = client.get_calls_status(settlement.bundle_id).await else {
            // retry on API error
            let _ = settlement.tx.clone().send(settlement);
            continue;
        };

        check_settlement_status(settlement, &status, &failed_counter).await;
    }

    info!("Settlement worker finished");
}

#[derive(Debug, Parser)]
#[command(author, about = "Relay stress tester", long_about = None)]
struct Args {
    /// RPC URL of the relay for relay_ namespace calls.
    #[arg(long = "relay-url", value_name = "RELAY_URL", required = true)]
    relay_url: Url,
    /// RPC URLs of the source chains
    #[arg(long = "src-rpc", value_name = "RPC_URL", required = false)]
    src_rpc: Vec<Url>,
    /// RPC URL of the destination chain
    #[arg(long = "dst-rpc", value_name = "RPC_URL", required = true)]
    dst_rpc: Url,
    /// Private key of the account to use for testing.
    ///
    /// This account should have sufficient fee tokens to cover the gas costs of the intents.
    #[arg(long = "private-key", value_name = "PRIVATE_KEY", required = true, env = "PK")]
    private_key: String,
    /// Address of the fee token to use for testing.
    #[arg(long = "fee-token", value_name = "ADDRESS", required = true)]
    fee_token: Address,
    /// Amount of fee tokens to fund each account with in wei.
    #[arg(long = "fee-token-amount", value_name = "AMOUNT", default_value_t = U256::from(ETH_TO_WEI * 10))]
    fee_token_amount: U256,
    /// Number of accounts to create and test with.
    #[arg(long = "accounts", value_name = "COUNT", default_value_t = 1000)]
    accounts: usize,
    /// The amount to transfer out from the EOA on every transfer. The amount will be transferred
    /// to the signer.
    #[arg(long = "transfer-amount", value_name = "AMOUNT", default_value_t = U256::from(ETH_TO_WEI))]
    transfer_amount: U256,
}

impl Args {
    async fn run(self) -> eyre::Result<()> {
        let tester = StressTester::new(self).await?;

        tester.spawn().await
    }
}

#[tokio::main]
async fn main() {
    init_logging();

    let args = Args::parse();
    if let Err(err) = args.run().await {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}

/// Build a mapping of chain IDs to fee token addresses for a given fee token
async fn build_fee_token_map(
    caps: &RelayCapabilities,
    chain_ids: &[ChainId],
    fee_token: Address,
) -> eyre::Result<Arc<HashMap<ChainId, Address>>> {
    // Find the fee token kind from the first chain that has it
    let fee_token_uid = caps
        .0
        .values()
        .flat_map(|chain_caps| &chain_caps.fees.tokens)
        .find(|token| token.asset.address == fee_token)
        .ok_or_else(|| eyre::eyre!("fee token {} not found in any chain", fee_token))?
        .uid
        .clone();

    info!("Fee token {} has kind {:?}", fee_token, fee_token_uid);

    // Build a mapping of chain_id -> fee token address for this kind
    let mut fee_token_map = HashMap::new();
    for (chain_id, chain_caps) in &caps.0 {
        if let Some(token) = chain_caps.fees.tokens.iter().find(|t| t.uid == fee_token_uid) {
            fee_token_map.insert(*chain_id, token.asset.address);
            info!(
                "Chain {} has {} token at address {}",
                chain_id, fee_token_uid, token.asset.address
            );
        }
    }

    // Verify all chains support the fee token kind
    for chain_id in chain_ids {
        if !fee_token_map.contains_key(chain_id) {
            eyre::bail!("fee token uid {:?} is not supported on chain {}", fee_token_uid, chain_id,);
        }
    }

    Ok(Arc::new(fee_token_map))
}

#[instrument(level = "info", skip_all, fields(chain_id = tracing::field::Empty))]
async fn fund_accounts(
    provider: &DynProvider,
    accounts: Vec<StressAccount>,
    signer: DynSigner,
    fee_token_map: Arc<HashMap<ChainId, Address>>,
    fee_token_amount: U256,
    disperse_address: Address,
) -> eyre::Result<()> {
    let chain_id = provider.get_chain_id().await?;
    tracing::Span::current().record("chain_id", chain_id);

    let fee_token_address = fee_token_map
        .get(&chain_id)
        .ok_or_else(|| eyre::eyre!("no fee token mapping for chain {}", chain_id))?;
    if provider.get_code_at(disperse_address).await?.is_empty() {
        info!("Deploying Disperse contract");
        let receipt: alloy::rpc::types::TransactionReceipt = provider
            .send_transaction(
                TransactionRequest::default()
                    .to(CREATE2_DEPLOYER)
                    .input((B256::ZERO, &Disperse::BYTECODE).abi_encode_packed().into()),
            )
            .await?
            .get_receipt()
            .await?;
        assert!(receipt.status());
        info!("Deployed Disperse contract");
    }

    let disperse = Disperse::new(disperse_address, &provider);

    if !fee_token_address.is_zero() {
        let fee_token = IERC20Instance::new(*fee_token_address, &provider);
        if fee_token.allowance(signer.address(), disperse_address).call().await?
            < fee_token_amount * U256::from(accounts.len())
        {
            info!("Approving Disperse contract for token {fee_token_address}");
            fee_token.approve(disperse_address, U256::MAX).send().await?.get_receipt().await?;
            info!("Approved Disperse contract for token {fee_token_address}");
        }
    }

    let mut funded = 0;
    for batch in accounts.chunks(50) {
        info!("Funding accounts #{}..{}/{}", funded, funded + batch.len(), accounts.len());

        let recipients = batch.iter().map(|acc| acc.address).collect::<Vec<_>>();
        let values = std::iter::repeat_n(fee_token_amount, batch.len()).collect::<Vec<_>>();

        if !fee_token_address.is_zero() {
            disperse
                .disperseToken(*fee_token_address, recipients, values)
                .send()
                .await?
                .get_receipt()
                .await?;
        } else {
            disperse
                .disperseEther(recipients, values)
                .value(U256::from(batch.len()) * fee_token_amount)
                .send()
                .await?
                .get_receipt()
                .await?;
        }

        info!("Funded accounts #{}..{}/{}", funded, funded + batch.len(), accounts.len());
        funded += batch.len();
    }

    Ok(())
}
