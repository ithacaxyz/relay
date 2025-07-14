//! Relay configuration.
use crate::{
    constants::{DEFAULT_MAX_TRANSACTIONS, DEFAULT_NUM_SIGNERS, INTENT_GAS_BUFFER, TX_GAS_BUFFER},
    interop::{LayerZeroSettler, SettlementProcessor, Settler, SimpleSettler},
    liquidity::bridge::{BinanceBridgeConfig, SimpleBridgeConfig},
    storage::RelayStorage,
};
use alloy::{
    primitives::{Address, ChainId, map::HashMap},
    providers::{DynProvider, utils::EIP1559_FEE_ESTIMATION_REWARD_PERCENTILE},
    signers::local::coins_bip39::{English, Mnemonic},
};
use alloy_chains::Chain;
use eyre::Context;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr},
    path::Path,
    str::FromStr,
    time::Duration,
};

/// Relay configuration.
#[derive(Debug, Serialize, Deserialize)]
pub struct RelayConfig {
    /// Server configuration.
    pub server: ServerConfig,
    /// Chain configuration.
    pub chain: ChainConfig,
    /// Quote configuration.
    pub quote: QuoteConfig,
    /// Onramp configuration.
    pub onramp: OnrampConfig,
    /// Email configuration.
    #[serde(default)]
    pub email: EmailConfig,
    /// Transaction service configuration.
    pub transactions: TransactionServiceConfig,
    /// Interop configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interop: Option<InteropConfig>,
    /// Orchestrator address.
    pub orchestrator: Address,
    /// Previously deployed orchestrators.
    pub legacy_orchestrators: BTreeSet<Address>,
    /// Previously deployed delegation proxies.
    pub legacy_delegation_proxies: BTreeSet<Address>,
    /// Delegation proxy address.
    pub delegation_proxy: Address,
    /// Simulator address.
    pub simulator: Address,
    /// Funder address.
    pub funder: Address,
    /// Escrow address.
    pub escrow: Address,
    /// Secrets.
    #[serde(skip_serializing, default)]
    pub secrets: SecretsConfig,
    /// Database URL.
    pub database_url: Option<String>,
}

/// Server configuration.
#[derive(Debug, Serialize, Deserialize)]
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

/// Chain configuration.
#[derive(Debug, Serialize, Deserialize)]
pub struct ChainConfig {
    /// The RPC endpoint of a chain to send transactions to.
    pub endpoints: Vec<Url>,
    /// Mapping of a chain ID to RPC endpoint of the sequencer for OP rollups.
    #[serde(with = "crate::serde::hash_map")]
    pub sequencer_endpoints: HashMap<Chain, Url>,
    /// A fee token the relay accepts.
    pub fee_tokens: Vec<Address>,
    /// A token that is supported for interop.
    pub interop_tokens: Vec<Address>,
    /// The fee recipient address.
    ///
    /// Defaults to `Address::ZERO`, which means the fees will be accrued by the orchestrator
    /// contract.
    pub fee_recipient: Address,
    /// Optional rebalance service configuration.
    ///
    /// If provided, this relay instance will handle rebalancing of liquidity across chains.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rebalance_service: Option<RebalanceServiceConfig>,
}

/// Quote configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Gas estimate configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

/// Onramp configuration.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OnrampConfig {
    /// Banxa API configuration.
    pub banxa: BanxaConfig,
}

/// Email configuration.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailConfig {
    /// Resend API key.
    pub resend_api_key: Option<String>,
    /// Porto base URL.
    pub porto_base_url: Option<String>,
}

/// Banxa API configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BanxaConfig {
    /// Base URL for Banxa API.
    pub api_url: Url,
    /// Blockchain identifier for Banxa requests.
    pub blockchain: String,
    /// Banxa Secrets (API key, Webhook secret, Webhook Key)
    pub secrets: BanxaSecrets,
}

/// Banxa Secrets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanxaSecrets {
    /// Banxa API key.
    pub api_key: String,
}

impl Default for BanxaConfig {
    fn default() -> Self {
        Self {
            api_url: "https://api.banxa-sandbox.com".parse().expect("valid URL"),
            blockchain: "base".to_string(),
            secrets: BanxaSecrets { api_key: "".to_string() },
        }
    }
}

/// Secrets (kept out of serialized output).
#[derive(Debug, Deserialize)]
pub struct SecretsConfig {
    /// The secret key to sign transactions with.
    #[serde(with = "alloy::serde::displayfromstr")]
    pub signers_mnemonic: Mnemonic<English>,
    /// The funder KMS key or private key
    pub funder_key: String,
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
        }
    }
}

/// Interop configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

/// Configuration for the settler service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlerConfig {
    /// Settler implementation configuration.
    #[serde(flatten)]
    pub implementation: SettlerImplementation,
    /// Timeout for waiting for settlement verification.
    #[serde(with = "crate::serde::duration")]
    pub wait_verification_timeout: Duration,
}

/// Settler implementation configuration (mutually exclusive).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlerImplementation {
    /// LayerZero configuration for cross-chain settlement.
    LayerZero(LayerZeroConfig),
    /// Simple settler configuration for testing.
    Simple(SimpleSettlerConfig),
}

impl SettlerConfig {
    /// Creates a settlement processor from this configuration.
    pub fn settlement_processor(
        &self,
        storage: RelayStorage,
        providers: alloy::primitives::map::HashMap<ChainId, DynProvider>,
    ) -> eyre::Result<SettlementProcessor> {
        // Create the settler based on config
        let settler: Box<dyn Settler> = match &self.implementation {
            SettlerImplementation::LayerZero(config) => {
                Box::new(config.create_settler(providers, storage.clone()))
            }
            SettlerImplementation::Simple(config) => Box::new(config.create_settler()),
        };

        Ok(SettlementProcessor::new(settler))
    }
}

/// Simple settler configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleSettlerConfig {
    /// The address of the simple settler contract.
    pub settler_address: Address,
}

impl SimpleSettlerConfig {
    /// Creates a new simple settler instance.
    pub fn create_settler(&self) -> SimpleSettler {
        SimpleSettler::new(self.settler_address)
    }
}

/// LayerZero configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerZeroConfig {
    /// Mapping of chain ID to LayerZero endpoint ID.
    /// Format: { chain_id: endpoint_id }
    /// Example: { 1: 30101, 10: 30110 } means Ethereum mainnet (1) -> LayerZero EID 30101
    #[serde(with = "crate::serde::hash_map")]
    pub endpoint_ids: HashMap<ChainId, u32>,
    /// Mapping of chain ID to LayerZero endpoint address.
    #[serde(with = "crate::serde::hash_map")]
    pub endpoint_addresses: HashMap<ChainId, Address>,
    /// LayerZero settler contract address.
    pub settler_address: Address,
}

impl LayerZeroConfig {
    /// Creates a new LayerZero settler instance with the given providers and storage.
    pub fn create_settler(
        &self,
        providers: HashMap<ChainId, DynProvider>,
        storage: RelayStorage,
    ) -> LayerZeroSettler {
        LayerZeroSettler::new(
            self.endpoint_ids.clone().into_iter().collect(),
            self.endpoint_addresses.clone().into_iter().collect(),
            providers,
            self.settler_address,
            storage,
        )
    }
}

/// Configuration for transaction service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionServiceConfig {
    /// Number of signers to derive from mnemonic and use for sending transactions.
    pub num_signers: usize,
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
    /// Percentile of the priority fees to use for the transactions.
    pub priority_fee_percentile: f64,
}

impl Default for TransactionServiceConfig {
    fn default() -> Self {
        Self {
            num_signers: DEFAULT_NUM_SIGNERS,
            max_pending_transactions: DEFAULT_MAX_TRANSACTIONS,
            max_transactions_per_signer: 16,
            balance_check_interval: Duration::from_secs(5),
            nonce_check_interval: Duration::from_secs(60),
            transaction_timeout: Duration::from_secs(60),
            max_queued_per_eoa: 1,
            public_node_endpoints: HashMap::default(),
            priority_fee_percentile: EIP1559_FEE_ESTIMATION_REWARD_PERCENTILE,
        }
    }
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 9119,
                metrics_port: 9000,
                max_connections: 1000,
            },
            chain: ChainConfig {
                endpoints: vec![],
                sequencer_endpoints: HashMap::default(),
                fee_tokens: vec![],
                interop_tokens: vec![],
                fee_recipient: Address::ZERO,
                rebalance_service: None,
            },
            quote: QuoteConfig {
                constant_rate: None,
                gas: GasConfig { intent_buffer: INTENT_GAS_BUFFER, tx_buffer: TX_GAS_BUFFER },
                ttl: Duration::from_secs(5),
                rate_ttl: Duration::from_secs(300),
            },
            onramp: OnrampConfig::default(),
            email: EmailConfig::default(),
            transactions: TransactionServiceConfig::default(),
            interop: None,
            legacy_orchestrators: BTreeSet::new(),
            legacy_delegation_proxies: BTreeSet::new(),
            orchestrator: Address::ZERO,
            delegation_proxy: Address::ZERO,
            simulator: Address::ZERO,
            funder: Address::ZERO,
            escrow: Address::ZERO,
            secrets: SecretsConfig::default(),
            database_url: None,
        }
    }
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

    /// Extends the list of fee tokens that the relay accepts.
    pub fn with_fee_tokens(mut self, fee_tokens: &[Address]) -> Self {
        self.chain.fee_tokens.extend_from_slice(fee_tokens);
        self
    }

    /// Extends the list of interop tokens that the relay accepts.
    pub fn with_interop_tokens(mut self, interop_tokens: &[Address]) -> Self {
        self.chain.interop_tokens.extend_from_slice(interop_tokens);
        self
    }

    /// Extends the list of RPC endpoints (as URLs) for the chain transactions.
    pub fn with_endpoints(mut self, endpoints: &[Url]) -> Self {
        self.chain.endpoints.extend_from_slice(endpoints);
        self
    }

    /// Extends the list of sequencer RPC endpoints.
    pub fn with_sequencer_endpoints(
        mut self,
        endpoints: impl IntoIterator<Item = (Chain, Url)>,
    ) -> Self {
        self.chain.sequencer_endpoints.extend(endpoints);
        self
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
        self.chain.fee_recipient = fee_recipient;
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

    /// Sets the number of signers to derive from mnemonic and use for sending transactions.
    pub fn with_num_signers(mut self, num_signers: usize) -> Self {
        self.transactions.num_signers = num_signers;
        self
    }

    /// Sets the percentile of the priority fees to use for the transactions.
    pub fn with_priority_fee_percentile(mut self, percentile: f64) -> Self {
        self.transactions.priority_fee_percentile = percentile;
        self
    }

    /// Sets the Banxa API URL.
    pub fn with_banxa_api_url(mut self, api_url: Url) -> Self {
        self.onramp.banxa.api_url = api_url;
        self
    }

    /// Sets the Banxa API key.
    pub fn with_banxa_api_key(mut self, api_key: String) -> Self {
        self.onramp.banxa.secrets.api_key = api_key;
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
        self.chain.rebalance_service = config;
        self
    }

    /// Sets the funder signing key used to sign fund operations.
    pub fn with_funder_key(mut self, funder_key: String) -> Self {
        self.secrets.funder_key = funder_key;
        self
    }

    /// Sets the interop configuration.
    pub fn with_interop_config(mut self, interop_config: InteropConfig) -> Self {
        self.interop = Some(interop_config);
        self
    }

    /// Sets the funder owner key, and enables the rebalance service.
    pub fn with_funder_owner_key(mut self, funder_owner_key: String) -> Self {
        let Some(rebalance_service) = self.chain.rebalance_service.as_mut() else { return self };
        rebalance_service.funder_owner_key = funder_owner_key;
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
        let Some(rebalance_service) = self.chain.rebalance_service.as_mut() else { return self };

        if rebalance_service.binance.is_none() {
            rebalance_service.binance = Some(BinanceBridgeConfig { api_key, api_secret });
        } else {
            rebalance_service.binance.as_mut().unwrap().api_key = api_key;
            rebalance_service.binance.as_mut().unwrap().api_secret = api_secret;
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
}
