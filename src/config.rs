//! Relay configuration.
use crate::{
    constants::{DEFAULT_MAX_TRANSACTIONS, DEFAULT_NUM_SIGNERS, INTENT_GAS_BUFFER, TX_GAS_BUFFER},
    interop::{LayerZeroSettler, SettlementError, SettlementProcessor, Settler, SimpleSettler},
    liquidity::bridge::{BinanceBridgeConfig, SimpleBridgeConfig},
    signers::DynSigner,
    storage::RelayStorage,
    transactions::{MIN_SIGNER_GAS, TOP_UP_MULTIPLIER},
    types::{AssetUid, Assets, TransactionServiceHandles},
};
use alloy::{
    eips::eip1559::Eip1559Estimation,
    primitives::{
        Address, ChainId, U256,
        map::{HashMap, HashSet},
    },
    providers::{
        DynProvider,
        utils::{EIP1559_FEE_ESTIMATION_REWARD_PERCENTILE, Eip1559Estimator},
    },
    rpc::types::FeeHistory,
    signers::local::{
        PrivateKeySigner,
        coins_bip39::{English, Mnemonic},
    },
};
use alloy_chains::Chain;
use eyre::Context;
use reqwest::Url;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr},
    path::Path,
    str::FromStr,
    time::Duration,
};
use tracing::{info, warn};

// todo(onbjerg): We should consider merging the contract addresses into a `ContractConfig` struct,
// which would 1) make the config more readable and 2) simplify things like fetching
// [`VersionedContracts`].
/// Relay configuration.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    /// Server configuration.
    pub server: ServerConfig,
    /// Chain configurations.
    #[serde(with = "crate::serde::hash_map")]
    pub chains: HashMap<Chain, ChainConfig>,
    /// Quote configuration.
    #[serde(default)]
    pub quote: QuoteConfig,
    /// Email configuration.
    #[serde(default)]
    pub email: EmailConfig,
    /// Transaction service configuration.
    #[serde(default)]
    pub transactions: TransactionServiceConfig,
    /// Interop configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interop: Option<InteropConfig>,
    /// Orchestrator address.
    pub orchestrator: Address,
    /// Previously deployed orchestrators and simulators.
    ///
    /// Orchestrators and simulators should be of the same version to be compatible with each
    /// other.
    #[serde(default)]
    pub legacy_orchestrators: HashSet<LegacyOrchestrator>,
    /// Previously deployed delegation proxies.
    #[serde(default)]
    pub legacy_delegation_proxies: BTreeSet<Address>,
    /// Delegation proxy address.
    pub delegation_proxy: Address,
    /// Simulator address.
    pub simulator: Address,
    /// Funder address.
    pub funder: Address,
    /// Escrow address.
    pub escrow: Address,
    /// Fee recipient.
    pub fee_recipient: Address,
    /// Optional rebalance service configuration.
    ///
    /// If provided, this relay instance will handle rebalancing of liquidity across chains.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rebalance_service: Option<RebalanceServiceConfig>,
    /// Price feed config.
    #[serde(default)]
    pub pricefeed: PriceFeedConfig,
    /// Secrets.
    #[serde(skip_serializing, default)]
    pub secrets: SecretsConfig,
    /// Database URL.
    pub database_url: Option<String>,
}

impl RelayConfig {
    /// Sets the IP address to serve the RPC on.
    pub fn with_address(mut self, address: IpAddr) -> Self {
        self.server.address = address;
        self
    }

    /// Sets the port to serve the RPC on.
    pub fn with_port(mut self, port: u16) -> Self {
        self.server.port = port;
        self
    }

    /// Sets the port to serve the metrics on.
    pub fn with_metrics_port(mut self, port: u16) -> Self {
        self.server.metrics_port = port;
        self
    }

    /// Sets the maximum number of concurrent connections the relay can handle.
    pub fn with_max_connections(mut self, max_connections: u32) -> Self {
        self.server.max_connections = max_connections;
        self
    }

    /// Sets the lifetime duration for fee quotes.
    pub fn with_quote_ttl(mut self, quote_ttl: Duration) -> Self {
        self.quote.ttl = quote_ttl;
        self
    }

    /// Sets the lifetime duration for token price rates.
    pub fn with_rate_ttl(mut self, rate_ttl: Duration) -> Self {
        self.quote.rate_ttl = rate_ttl;
        self
    }

    /// Sets a constant rate for the price oracle. Used for testing.
    pub fn with_quote_constant_rate(mut self, constant_rate: Option<f64>) -> Self {
        self.quote.constant_rate = constant_rate.or(self.quote.constant_rate);
        self
    }

    /// Sets the buffer added to Intent gas estimates.
    pub fn with_intent_gas_buffer(mut self, buffer: u64) -> Self {
        self.quote.gas.intent_buffer = buffer;
        self
    }

    /// Sets the buffer added to tx gas estimates.
    pub fn with_tx_gas_buffer(mut self, buffer: u64) -> Self {
        self.quote.gas.tx_buffer = buffer;
        self
    }

    /// Set the chains.
    pub fn with_chains(self, chains: HashMap<Chain, ChainConfig>) -> Self {
        Self { chains, ..self }
    }

    /// Extends the list of public node RPC endpoints.
    pub fn with_public_node_endpoints(
        mut self,
        endpoints: impl IntoIterator<Item = (Chain, Url)>,
    ) -> Self {
        self.transactions.public_node_endpoints.extend(endpoints);
        self
    }

    /// Sets the fee recipient address.
    pub fn with_fee_recipient(mut self, fee_recipient: Address) -> Self {
        self.fee_recipient = fee_recipient;
        self
    }

    /// Sets the secret key used to sign transactions.
    pub fn with_signers_mnemonic(mut self, mnemonic: Mnemonic<English>) -> Self {
        self.secrets.signers_mnemonic = mnemonic;
        self
    }

    /// Sets the orchestrator address.
    pub fn with_orchestrator(mut self, orchestrator: Option<Address>) -> Self {
        if let Some(orchestrator) = orchestrator {
            self.orchestrator = orchestrator;
        }
        self
    }

    /// Sets the delegation address.
    pub fn with_delegation_proxy(mut self, delegation_proxy: Option<Address>) -> Self {
        if let Some(delegation_proxy) = delegation_proxy {
            self.delegation_proxy = delegation_proxy;
        }
        self
    }

    /// Sets the legacy orchestrator addresses.
    pub fn with_legacy_orchestrators(
        mut self,
        legacy_orchestrators: &[LegacyOrchestrator],
    ) -> Self {
        self.legacy_orchestrators.extend(legacy_orchestrators);
        self
    }

    /// Sets the legacy delegation proxy addresses.
    pub fn with_legacy_delegation_proxies(mut self, legacy_delegation_proxies: &[Address]) -> Self {
        self.legacy_delegation_proxies.extend(legacy_delegation_proxies);
        self
    }

    /// Sets the simulator address.
    pub fn with_simulator(mut self, simulator: Option<Address>) -> Self {
        if let Some(simulator) = simulator {
            self.simulator = simulator;
        }
        self
    }

    /// Sets the funder address.
    pub fn with_funder(mut self, funder: Option<Address>) -> Self {
        if let Some(funder) = funder {
            self.funder = funder;
        }
        self
    }

    /// Sets the escrow address.
    pub fn with_escrow(mut self, escrow: Option<Address>) -> Self {
        if let Some(escrow) = escrow {
            self.escrow = escrow;
        }
        self
    }

    /// Sets the database URL.
    pub fn with_database_url(mut self, database_url: Option<String>) -> Self {
        self.database_url = database_url;
        self
    }

    /// Sets the maximum number of pending transactions.
    pub fn with_max_pending_transactions(mut self, max_pending_transactions: usize) -> Self {
        self.transactions.max_pending_transactions = max_pending_transactions;
        self
    }

    /// Sets the Resend API key.
    pub fn with_resend_api_key(mut self, api_key: Option<String>) -> Self {
        self.email.resend_api_key = api_key.or(self.email.resend_api_key);
        self
    }

    /// Sets the Porto base URL.
    pub fn with_porto_base_url(mut self, value: Option<String>) -> Self {
        self.email.porto_base_url = value.or(self.email.porto_base_url);
        self
    }

    /// Sets the configuration for the transaction service.
    pub fn with_transaction_service_config(mut self, config: TransactionServiceConfig) -> Self {
        self.transactions = config;
        self
    }

    /// Sets the rebalance service configuration.
    pub fn with_rebalance_service_config(mut self, config: Option<RebalanceServiceConfig>) -> Self {
        self.rebalance_service = config;
        self
    }

    /// Sets the funder signing key used to sign fund operations.
    pub fn with_funder_key(mut self, funder_key: Option<String>) -> Self {
        if let Some(funder_key) = funder_key {
            self.secrets.funder_key = funder_key;
        }
        self
    }

    /// Sets the service API key for protected RPC endpoints.
    pub fn with_service_api_key(mut self, service_api_key: Option<String>) -> Self {
        self.secrets.service_api_key = service_api_key.or(self.secrets.service_api_key);
        self
    }

    /// Sets the interop configuration.
    pub fn with_interop_config(mut self, interop_config: InteropConfig) -> Self {
        self.interop = Some(interop_config);
        self
    }

    /// Sets the funder owner key, and enables the rebalance service.
    pub fn with_funder_owner_key(mut self, funder_owner_key: Option<String>) -> Self {
        let Some(key) = funder_owner_key else { return self };
        let Some(rebalance_service) = self.rebalance_service.as_mut() else { return self };
        rebalance_service.funder_owner_key = key;
        self
    }

    /// Sets the Binance API key and secret.
    pub fn with_binance_keys(
        mut self,
        api_key: Option<String>,
        api_secret: Option<String>,
    ) -> Self {
        let (api_key, api_secret) = match (api_key, api_secret) {
            (Some(api_key), Some(api_secret)) => (api_key, api_secret),
            (None, None) => return self,
            _ => panic!("expected both Binance API key and secret"),
        };
        let Some(rebalance_service) = self.rebalance_service.as_mut() else { return self };

        if rebalance_service.binance.is_none() {
            rebalance_service.binance = Some(BinanceBridgeConfig { api_key, api_secret });
        } else {
            rebalance_service.binance.as_mut().unwrap().api_key = api_key;
            rebalance_service.binance.as_mut().unwrap().api_secret = api_secret;
        }

        self
    }

    /// Set the simple settler owner key if interop is already configured for simple settler.
    pub fn with_simple_settler_owner_key(mut self, settler_owner_key: Option<String>) -> Self {
        let Some(pk) = settler_owner_key else {
            warn!("no simple settler owner private key provided");
            return self;
        };

        if let Some(conf) = self.interop.as_mut().map(|conf| &mut conf.settler)
            && let SettlerImplementation::Simple(conf) = &mut conf.implementation
        {
            conf.private_key = Some(pk);
        }
        self
    }

    /// Load from a YAML file.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> eyre::Result<Self> {
        let path = path.as_ref();
        let file = std::fs::File::open(path)
            .wrap_err_with(|| format!("failed to read config file: {}", path.display()))?;
        let config = serde_yaml::from_reader(&file)
            .wrap_err_with(|| format!("failed to parse config file: {}", path.display()))?;
        Ok(config)
    }

    /// Save to a YAML file.
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> eyre::Result<()> {
        let content = serde_yaml::to_string(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Returns the max signer count across all configured chains.
    pub fn max_signer_count(&self) -> usize {
        self.chains.values().map(|chain| chain.signers.num_signers).max().unwrap_or_default()
    }
}

/// Server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// The address to serve the RPC on.
    pub address: IpAddr,
    /// The port to serve the RPC on.
    pub port: u16,
    /// The port to serve the metrics on.
    pub metrics_port: u16,
    /// The maximum number of concurrent connections the relay can handle.
    pub max_connections: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 9119,
            metrics_port: 9000,
            max_connections: 1000,
        }
    }
}

/// Chain configuration for individual chains.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChainConfig {
    /// The symbol of the native asset.
    #[serde(default)]
    pub native_symbol: Option<String>,
    /// The RPC endpoint of a chain to send transactions to.
    pub endpoint: Url,
    /// The sequencer URL, if any.
    #[serde(default)]
    pub sequencer: Option<Url>,
    /// Flashblocks streaming endpoint, if any.
    #[serde(default)]
    pub flashblocks: Option<Url>,
    /// The simulation mode to use for the chain.
    #[serde(default)]
    pub sim_mode: SimMode,
    /// Assets known for this chain.
    pub assets: Assets,
    /// Fee settings for this chain
    #[serde(default)]
    pub fees: FeeConfig,
    /// Number of signers to derive from mnemonic and use for sending transactions.
    #[serde(default)]
    pub signers: SignerConfig,
    /// The settler address for this chain.
    ///
    /// Required if the chain has any interop-enabled tokens.
    #[serde(default)]
    pub settler_address: Option<Address>,
}

/// Chain specific config for signers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignerConfig {
    /// Number of signers to derive from mnemonic and use for sending transactions.
    pub num_signers: usize,
}

impl Default for SignerConfig {
    fn default() -> Self {
        Self { num_signers: DEFAULT_NUM_SIGNERS }
    }
}

/// The signer balance config.
///
/// This is used to configure when to pause a signer, ie, when to wait for it to be funded before
/// signing transactions.
///
///
/// This can be either:
/// * A specific balance threshold in wei, or
/// * An amount of gas, the required balance to unpause will be calculated based on the current fee
///   before signing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", content = "value")]
pub enum SignerBalanceConfig {
    /// A specific balance threshold in wei
    Balance(U256),
    /// An amount of gas.
    Gas(U256),
}

impl SignerBalanceConfig {
    /// This determines the minimum balance based on the current settings and the provided gas
    /// price.
    ///
    /// For [SignerBalanceConfig::Balance], this just returns the configured balance.
    ///
    /// For [SignerBalanceConfig::Gas], this calculates the balance based on the configured gas and
    /// provided gas price
    pub fn minimum_signer_balance(&self, gas_price: u128) -> U256 {
        match self {
            Self::Balance(balance) => *balance,
            Self::Gas(gas) => gas * U256::from(gas_price),
        }
    }
}

/// Settings that affect fee estimation.
///
/// Across Ethereum L2s and EVM compatible L1s, various different fee rules exists that need special
/// handling, this type contains all fee related settings
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct FeeConfig {
    /// Percentile of the priority fees to use for the transactions.
    ///
    /// This is used to estimate the EIP-1559 fees via `eth_getFeeHistory`.
    pub priority_fee_percentile: f64,
    /// The minimum fee to set if any in wei.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_fee: Option<u64>,
    /// The min signer balance config to use.
    pub signer_balance_config: SignerBalanceConfig,
    /// The top up multiplier, this configures how much we will top up the signer account by when
    /// it becomes paused. The funding amount will be [`top_up_multiplier`], times the minimum
    /// signing balance calculated by [`FeeConfig::minimum_signer_balance`].
    pub top_up_multiplier: u64,
}

impl FeeConfig {
    /// Estimates EIP-1559 fees from fee history and adjusts them based on configured settings.
    ///
    /// This method:
    /// 1. Uses the `Eip1559Estimator` to calculate base fee estimates from the fee history
    /// 2. Adjusts the estimates to enforce minimum fees if configured
    ///
    /// Returns the adjusted [`Eip1559Estimation`].
    pub fn estimate_eip1559_fees(&self, fee_history: &FeeHistory) -> Eip1559Estimation {
        let fees = Eip1559Estimator::default().estimate(
            fee_history.latest_block_base_fee().unwrap_or_default(),
            fee_history.reward.as_deref().unwrap_or_default(),
        );
        self.adjusted_eip1559_estimation(fees)
    }

    /// Adjusts the estimated [`Eip1559Estimation`] based on the configured settings.
    ///
    /// - Enforces minimum fees, if any.
    ///
    /// See also [`Self::adjust_eip1559_estimation`].
    ///
    /// Returns the adjusted [`Eip1559Estimation`].
    pub fn adjusted_eip1559_estimation(&self, mut fees: Eip1559Estimation) -> Eip1559Estimation {
        self.adjust_eip1559_estimation(&mut fees);
        fees
    }

    /// Adjusts the estimated [`Eip1559Estimation`] based on the configured settings.
    /// - Enforces minimum fees, if any.
    ///
    /// This ensures that, in case the given estimation is lower than the required minimum, the fees
    /// are adjusted to satisfy the minimum. This is mainly relevant for chains that have a
    /// special/fake concept of EIP-1559 where a fixed prio fee minimum is required, and this
    /// function acts as a sanity check that bumps the fees in case the estimation is too low. A
    /// low estimation via `eth_getFeeHistory` that does not satisfy the minimum fee is possible for
    /// example, if the block contains various system transactions with `gasPrice == 0` at the end
    /// of the block (e.g. BSC does this).
    ///
    /// See Polygon: <https://docs.polygon.technology/tools/gas/polygon-gas-station/>
    pub fn adjust_eip1559_estimation(&self, fees: &mut Eip1559Estimation) {
        if let Some(minimum) = self.minimum_fee.map(u128::from)
            && fees.max_priority_fee_per_gas < minimum
        {
            // Ensure that the prio fee is the configured minimum and adjust the max fee
            // accordingly, because prio fee <= max fee
            fees.max_priority_fee_per_gas = minimum;
            fees.max_fee_per_gas = minimum;
        }
    }

    /// Returns the minimum signer balance based on the current [`SignerBalanceConfig`] and the
    /// provided gas price.
    ///
    /// If the [`SignerBalanceConfig`] is set to [`SignerBalanceConfig::Balance`], this will return
    /// the configured balance regardless of the gas price.
    ///
    /// See also [`SignerBalanceConfig::minimum_signer_balance`].
    pub fn minimum_signer_balance(&self, gas_price: u128) -> U256 {
        self.signer_balance_config.minimum_signer_balance(gas_price)
    }

    /// Returns the amount to top up the signer account by, by multiplying the
    /// [`SignerBalanceConfig`] with the top up multiplier.
    pub fn top_up_amount(&self, gas_price: u128) -> U256 {
        self.minimum_signer_balance(gas_price) * U256::from(self.top_up_multiplier)
    }
}

impl Default for FeeConfig {
    fn default() -> Self {
        Self {
            priority_fee_percentile: EIP1559_FEE_ESTIMATION_REWARD_PERCENTILE,
            minimum_fee: None,
            signer_balance_config: SignerBalanceConfig::Gas(MIN_SIGNER_GAS),
            top_up_multiplier: TOP_UP_MULTIPLIER,
        }
    }
}

/// The simulation mode to use for intent simulation on a specific chain.
///
/// Defaults to [`SimMode::SimulateV1`] which will simulate intents using `eth_simulateV1`. For
/// chains that do not have a working `eth_simulateV1` implementation, use [`SimMode::Trace`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SimMode {
    /// Use `eth_simulateV1`
    #[default]
    SimulateV1,
    /// Use `debug_trace`.
    Trace,
}

impl SimMode {
    /// Returns true if this is [`SimMode::SimulateV1`]
    pub const fn is_simulate_v1(&self) -> bool {
        matches!(self, Self::SimulateV1)
    }
}

/// Quote configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuoteConfig {
    /// Sets a constant rate for the price oracle. Used for testing.
    pub constant_rate: Option<f64>,
    /// Gas estimate configuration.
    gas: GasConfig,
    /// The lifetime of a fee quote.
    #[serde(with = "crate::serde::duration")]
    pub ttl: Duration,
    /// The lifetime of a price rate.
    #[serde(with = "crate::serde::duration")]
    pub rate_ttl: Duration,
}

impl Default for QuoteConfig {
    fn default() -> Self {
        Self {
            constant_rate: None,
            gas: GasConfig { intent_buffer: INTENT_GAS_BUFFER, tx_buffer: TX_GAS_BUFFER },
            ttl: Duration::from_secs(5),
            rate_ttl: Duration::from_secs(300),
        }
    }
}

/// Gas estimate configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GasConfig {
    /// Extra buffer added to Intent gas estimates.
    pub intent_buffer: u64,
    /// Extra buffer added to transaction gas estimates.
    pub tx_buffer: u64,
}

impl QuoteConfig {
    /// Returns the configured extra buffer added to intent gas estimates.
    pub fn intent_buffer(&self) -> u64 {
        self.gas.intent_buffer
    }

    /// Returns the configured extra buffer added to transaction gas estimates.
    pub fn tx_buffer(&self) -> u64 {
        self.gas.tx_buffer
    }
}

/// Email configuration.
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailConfig {
    /// Resend API key.
    pub resend_api_key: Option<String>,
    /// Porto base URL.
    pub porto_base_url: Option<String>,
}

/// Secrets (kept out of serialized output).
#[derive(Debug, Clone, Deserialize)]
pub struct SecretsConfig {
    /// The secret key to sign transactions with.
    #[serde(with = "alloy::serde::displayfromstr")]
    pub signers_mnemonic: Mnemonic<English>,
    /// The funder KMS key or private key
    pub funder_key: String,
    /// API key for protected RPC endpoints
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_api_key: Option<String>,
}

impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            signers_mnemonic: Mnemonic::<English>::from_str(
                "test test test test test test test test test test test junk",
            )
            .unwrap(),
            funder_key: "0x0000000000000000000000000000000000000000000000000000000000000001"
                .to_string(),
            service_api_key: None,
        }
    }
}

/// Interop configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteropConfig {
    /// Interval for checking pending refunds.
    #[serde(with = "crate::serde::duration")]
    pub refund_check_interval: Duration,
    /// Time threshold in seconds before refunds can be processed for escrows.
    pub escrow_refund_threshold: u64,
    /// Settler configuration.
    pub settler: SettlerConfig,
}

/// Configuration for the rebalance service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebalanceServiceConfig {
    /// Configuration for the Binance bridge. If provided, Binance will be used to rebalance funds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binance: Option<BinanceBridgeConfig>,
    /// Configuration for the simple bridge. If provided, Simple will be used to rebalance funds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub simple: Option<SimpleBridgeConfig>,
    /// The private key of the funder account owner. Required for pulling funds from the funders.
    #[serde(default)]
    pub funder_owner_key: String,
    /// Mapping of asset identifiers to rebalance threshold.
    #[serde(default, skip_serializing_if = "HashMap::is_empty", with = "crate::serde::hash_map")]
    pub thresholds: HashMap<AssetUid, Decimal>,
}

/// Configuration for price feeds.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PriceFeedConfig {
    /// Configuration for CoinGecko.
    #[serde(default)]
    pub coingecko: CoinGeckoConfig,
}

/// Configuration for CoinGecko.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CoinGeckoConfig {
    /// A map of asset UIDs to CoinGecko coin IDs.
    #[serde(default)]
    pub remapping: HashMap<AssetUid, String>,
}

/// Configuration for the settler service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlerConfig {
    /// Settler implementation configuration.
    #[serde(flatten)]
    pub implementation: SettlerImplementation,
    /// Timeout for waiting for settlement verification.
    #[serde(with = "crate::serde::duration")]
    pub wait_verification_timeout: Duration,
}

impl SettlerConfig {
    /// Creates a settlement processor from this configuration.
    pub async fn settlement_processor(
        &self,
        storage: RelayStorage,
        providers: alloy::primitives::map::HashMap<ChainId, DynProvider>,
        tx_service_handles: TransactionServiceHandles,
    ) -> eyre::Result<SettlementProcessor> {
        // Create the settler based on config
        let settler: Box<dyn Settler> = match &self.implementation {
            SettlerImplementation::LayerZero(config) => Box::new(
                config.create_settler(providers, storage.clone(), tx_service_handles).await?,
            ),
            SettlerImplementation::Simple(config) => Box::new(config.create_settler(providers)?),
        };

        Ok(SettlementProcessor::new(settler))
    }
}

/// Settler implementation configuration (mutually exclusive).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlerImplementation {
    /// LayerZero configuration for cross-chain settlement.
    LayerZero(LayerZeroConfig),
    /// Simple settler configuration for testing.
    Simple(SimpleSettlerConfig),
}

/// Simple settler configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimpleSettlerConfig {
    /// Private key for signing settlement write operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
}

impl SimpleSettlerConfig {
    /// Creates a new simple settler instance.
    pub fn create_settler(
        &self,
        providers: HashMap<ChainId, DynProvider>,
    ) -> eyre::Result<SimpleSettler> {
        let signer = self
            .private_key
            .as_ref()
            .ok_or_else(|| eyre::eyre!("no settler private key"))?
            .parse::<PrivateKeySigner>()
            .map_err(|e| eyre::eyre!("Invalid private key: {}", e))?;

        Ok(SimpleSettler::new(signer, providers))
    }
}

/// LayerZero configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerZeroConfig {
    /// Mapping of chain ID to LayerZero endpoint address.
    #[serde(with = "crate::serde::hash_map")]
    pub endpoint_addresses: HashMap<ChainId, Address>,
    /// LayerZero settler signer key (hex private key or KMS ARN)
    /// Can be set via environment variable ${RELAY_SETTLER_SIGNER_KEY} or in the config file
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settler_signer_key: Option<String>,
}

impl LayerZeroConfig {
    /// Creates a new LayerZero settler instance with the given providers and storage.
    pub async fn create_settler(
        &self,
        providers: HashMap<ChainId, DynProvider>,
        storage: RelayStorage,
        tx_service_handles: TransactionServiceHandles,
    ) -> Result<LayerZeroSettler, SettlementError> {
        let key = self.settler_signer_key.clone()
            .or_else(|| std::env::var("RELAY_SETTLER_SIGNER_KEY").ok())
            .ok_or_else(|| SettlementError::InternalError(
                "LayerZero settler signer key required (config or RELAY_SETTLER_SIGNER_KEY env)".to_string()
            ))?;

        let settler_signer = DynSigner::from_raw(&key).await.map_err(|e| {
            SettlementError::InternalError(format!("Failed to parse L0 settler signer: {}", e))
        })?;

        info!(address = ?settler_signer.address(), "LayerZero settler signer configured.");

        LayerZeroSettler::new(
            self.endpoint_addresses.clone(),
            providers,
            storage,
            tx_service_handles,
            settler_signer,
        )
        .await
    }
}

/// Configuration for transaction service.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransactionServiceConfig {
    /// Maximum number of transactions that can be pending at any given time.
    pub max_pending_transactions: usize,
    /// Maximum number of pending transactions that can be handled by a single signer.
    pub max_transactions_per_signer: usize,
    /// Maximum number of transactions that can be queued for a single EOA.
    pub max_queued_per_eoa: usize,
    /// Interval for checking signer balances.
    #[serde(with = "crate::serde::duration")]
    pub balance_check_interval: Duration,
    /// Interval for checking nonce gaps.
    #[serde(with = "crate::serde::duration")]
    pub nonce_check_interval: Duration,
    /// Timeout after which we consider transaction as failed, in seconds.
    #[serde(with = "crate::serde::duration")]
    pub transaction_timeout: Duration,
    /// Mapping of a chain ID to RPC endpoint of the public node for OP rollups that can be used
    /// for querying transactions.
    #[serde(with = "crate::serde::hash_map")]
    pub public_node_endpoints: HashMap<Chain, Url>,
}

impl Default for TransactionServiceConfig {
    fn default() -> Self {
        Self {
            max_pending_transactions: DEFAULT_MAX_TRANSACTIONS,
            max_transactions_per_signer: 16,
            balance_check_interval: Duration::from_secs(5),
            nonce_check_interval: Duration::from_secs(60),
            transaction_timeout: Duration::from_secs(60),
            max_queued_per_eoa: 1,
            public_node_endpoints: HashMap::default(),
        }
    }
}

/// Legacy orchestrator and simulator contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LegacyOrchestrator {
    /// Legacy orchestrator address.
    pub orchestrator: Address,
    /// Legacy simulator address.
    pub simulator: Address,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AssetDescriptor, AssetUid};
    use alloy::primitives::uint;
    use std::collections::HashMap;

    #[test]
    fn test_config_v21_yaml() {
        let s = include_str!("../tests/assets/config/v21.yaml");
        let config = serde_yaml::from_str::<RelayConfig>(s).unwrap();
        let yaml = serde_yaml::to_string(&config).unwrap();
        let from_yaml = serde_yaml::from_str::<RelayConfig>(&yaml).unwrap();
        assert_eq!(from_yaml.chains, config.chains);
        assert_eq!(from_yaml.pricefeed, config.pricefeed);
        assert_eq!(from_yaml.interop, config.interop);
        assert_eq!(from_yaml.transactions, config.transactions);
    }

    #[test]
    fn test_config_v22() {
        let s = include_str!("../tests/assets/config/v22.yaml");
        let config = serde_yaml::from_str::<RelayConfig>(s).unwrap();

        // Verify that chains have settler addresses based on whether they have interop tokens
        for (chain, chain_config) in &config.chains {
            // Chain 1 (mainnet) has interop tokens, so it should have a settler address
            if chain.id() == 1 {
                assert!(
                    chain_config.settler_address.is_some(),
                    "Chain 1 should have a settler address"
                );
                assert_eq!(
                    chain_config.settler_address.unwrap().to_string(),
                    "0x1111111111111111111111111111111111111111"
                );
                // Verify it actually has interop tokens
                assert!(
                    chain_config.assets.interop_iter().count() > 0,
                    "Chain 1 should have interop tokens"
                );
            }
            // Chain 10 (optimism) has interop tokens, so it should have a settler address
            else if chain.id() == 10 {
                assert!(
                    chain_config.settler_address.is_some(),
                    "Chain 10 should have a settler address"
                );
                assert_eq!(
                    chain_config.settler_address.unwrap().to_string(),
                    "0x2222222222222222222222222222222222222222"
                );
                // Verify it actually has interop tokens
                assert!(
                    chain_config.assets.interop_iter().count() > 0,
                    "Chain 10 should have interop tokens"
                );
            }
            // Chain 42161 (arbitrum) has no interop tokens, so settler_address should be None
            else if chain.id() == 42161 {
                assert!(
                    chain_config.settler_address.is_none(),
                    "Chain 42161 should not have a settler address"
                );
                // Verify it has no interop tokens
                assert_eq!(
                    chain_config.assets.interop_iter().count(),
                    0,
                    "Chain 42161 should not have interop tokens"
                );
            }
        }

        // Verify LayerZero config no longer has settler_address
        if let Some(interop) = &config.interop
            && let SettlerImplementation::LayerZero(lz_config) = &interop.settler.implementation
        {
            // This would fail to compile if settler_address field existed
            let _ = &lz_config.endpoint_addresses;
        }

        // Test round-trip serialization
        let yaml = serde_yaml::to_string(&config).unwrap();
        let from_yaml = serde_yaml::from_str::<RelayConfig>(&yaml).unwrap();
        assert_eq!(from_yaml.chains, config.chains);
        assert_eq!(from_yaml.pricefeed, config.pricefeed);
        assert_eq!(from_yaml.interop, config.interop);
        assert_eq!(from_yaml.transactions, config.transactions);
    }

    #[test]
    fn test_chain_config_yaml() {
        let s = r#"
endpoint: ws://execution-service.base-mainnet-stable.svc.cluster.local:8546/
sequencer: https://mainnet-sequencer-dedicated.base.org/
flashblocks: https://mainnet-preconf.base.org/
assets:
  ethereum:
    # Address 0 denotes the native asset and it must be present, even if it is not a fee token.
    address: "0x0000000000000000000000000000000000000000"
    fee_token: true
  usd-coin:
    address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    decimals: 6
    fee_token: false
    interop: false
sim_mode: trace
        "#;

        let config = serde_yaml::from_str::<ChainConfig>(s).unwrap();

        // Create expected ChainConfig manually
        let mut assets = HashMap::new();
        assets.insert(
            AssetUid::new("ethereum".to_string()),
            AssetDescriptor {
                address: Address::ZERO,
                decimals: 18,
                fee_token: true,
                interop: false,
            },
        );
        assets.insert(
            AssetUid::new("usd-coin".to_string()),
            AssetDescriptor {
                address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".parse().unwrap(),
                decimals: 6,
                fee_token: false,
                interop: false,
            },
        );

        let expected = ChainConfig {
            native_symbol: None,
            endpoint: "ws://execution-service.base-mainnet-stable.svc.cluster.local:8546/"
                .parse()
                .unwrap(),
            sequencer: Some("https://mainnet-sequencer-dedicated.base.org/".parse().unwrap()),
            flashblocks: Some("https://mainnet-preconf.base.org/".parse().unwrap()),
            sim_mode: SimMode::Trace,
            assets: Assets::new(assets),
            fees: Default::default(),
            signers: Default::default(),
            settler_address: None,
        };

        assert_eq!(config, expected);
    }

    #[test]
    fn test_chain_fee_config_yaml() {
        let s = r#"
endpoint: ws://execution-service.base-mainnet-stable.svc.cluster.local:8546/
sequencer: https://mainnet-sequencer-dedicated.base.org/
flashblocks: https://mainnet-preconf.base.org/
assets:
  ethereum:
    # Address 0 denotes the native asset and it must be present, even if it is not a fee token.
    address: "0x0000000000000000000000000000000000000000"
    fee_token: true
  usd-coin:
    address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    decimals: 6
    fee_token: false
    interop: false
sim_mode: trace
fees:
    minimum_fee: 100
        "#;

        let config = serde_yaml::from_str::<ChainConfig>(s).unwrap();
        assert_eq!(config.fees, FeeConfig { minimum_fee: Some(100), ..Default::default() });
    }

    #[test]
    fn test_chain_signer_config_yaml() {
        let s = r#"
endpoint: ws://execution-service.base-mainnet-stable.svc.cluster.local:8546/
sequencer: https://mainnet-sequencer-dedicated.base.org/
flashblocks: https://mainnet-preconf.base.org/
assets:
  ethereum:
    # Address 0 denotes the native asset and it must be present, even if it is not a fee token.
    address: "0x0000000000000000000000000000000000000000"
    fee_token: true
  usd-coin:
    address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    decimals: 6
    fee_token: false
    interop: false
sim_mode: trace
fees:
    minimum_fee: 100
signers:
    num_signers: 1000
        "#;

        let config = serde_yaml::from_str::<ChainConfig>(s).unwrap();
        assert_eq!(config.signers, SignerConfig { num_signers: 1000 });
    }

    #[test]
    fn signer_balance_config_gas_yaml() {
        let s = r#"
endpoint: ws://execution-service.base-mainnet-stable.svc.cluster.local:8546/
sequencer: https://mainnet-sequencer-dedicated.base.org/
flashblocks: https://mainnet-preconf.base.org/
assets:
  ethereum:
    # Address 0 denotes the native asset and it must be present, even if it is not a fee token.
    address: "0x0000000000000000000000000000000000000000"
    fee_token: true
  usd-coin:
    address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    decimals: 6
    fee_token: false
    interop: false
sim_mode: trace
fees:
    signer_balance_config:
        type: gas
        value: 100
            "#;

        let config = serde_yaml::from_str::<ChainConfig>(s).unwrap();
        assert_eq!(
            config.fees,
            FeeConfig {
                signer_balance_config: SignerBalanceConfig::Gas(uint!(100_U256)),
                ..Default::default()
            }
        );
    }

    #[test]
    fn signer_balance_config_balance_yaml() {
        let s = r#"
endpoint: ws://execution-service.base-mainnet-stable.svc.cluster.local:8546/
sequencer: https://mainnet-sequencer-dedicated.base.org/
flashblocks: https://mainnet-preconf.base.org/
assets:
  ethereum:
    # Address 0 denotes the native asset and it must be present, even if it is not a fee token.
    address: "0x0000000000000000000000000000000000000000"
    fee_token: true
  usd-coin:
    address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    decimals: 6
    fee_token: false
    interop: false
sim_mode: trace
fees:
    signer_balance_config:
        type: balance
        value: 100
            "#;

        let config = serde_yaml::from_str::<ChainConfig>(s).unwrap();
        assert_eq!(
            config.fees,
            FeeConfig {
                signer_balance_config: SignerBalanceConfig::Balance(uint!(100_U256)),
                ..Default::default()
            }
        );
    }

    #[test]
    fn signer_balance_config_default() {
        let s = r#"
endpoint: ws://execution-service.base-mainnet-stable.svc.cluster.local:8546/
sequencer: https://mainnet-sequencer-dedicated.base.org/
flashblocks: https://mainnet-preconf.base.org/
assets:
  ethereum:
    # Address 0 denotes the native asset and it must be present, even if it is not a fee token.
    address: "0x0000000000000000000000000000000000000000"
    fee_token: true
  usd-coin:
    address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    decimals: 6
    fee_token: false
    interop: false
sim_mode: trace
            "#;

        let config = serde_yaml::from_str::<ChainConfig>(s).unwrap();
        assert_eq!(
            config.fees,
            FeeConfig {
                signer_balance_config: SignerBalanceConfig::Gas(MIN_SIGNER_GAS),
                top_up_multiplier: TOP_UP_MULTIPLIER,
                ..Default::default()
            }
        );
    }

    #[test]
    fn top_up_multiplier_yaml() {
        let s = r#"
endpoint: ws://execution-service.base-mainnet-stable.svc.cluster.local:8546/
sequencer: https://mainnet-sequencer-dedicated.base.org/
flashblocks: https://mainnet-preconf.base.org/
assets:
  ethereum:
    # Address 0 denotes the native asset and it must be present, even if it is not a fee token.
    address: "0x0000000000000000000000000000000000000000"
    fee_token: true
  usd-coin:
    address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    decimals: 6
    fee_token: false
    interop: false
sim_mode: trace
fees:
    signer_balance_config:
        type: gas
        value: 100
    top_up_multiplier: 3
            "#;

        let config = serde_yaml::from_str::<ChainConfig>(s).unwrap();
        assert_eq!(
            config.fees,
            FeeConfig {
                signer_balance_config: SignerBalanceConfig::Gas(uint!(100_U256)),
                top_up_multiplier: 3,
                ..Default::default()
            }
        );
    }

    #[test]
    fn custom_signer_balance_top_up() {
        let config = FeeConfig {
            signer_balance_config: SignerBalanceConfig::Gas(uint!(100_U256)),
            top_up_multiplier: 5,
            ..Default::default()
        };

        let gas_price = 2;
        let top_up_amount = config.top_up_amount(gas_price);
        assert_eq!(uint!(1000_U256), top_up_amount);
    }
}
