use crate::{
    chains::Chain,
    config::{RelayConfig, SettlerImplementation},
    diagnostics::chain::IEIP712::eip712DomainCall,
    signers::DynSigner,
    types::{
        AssetDescriptor, AssetUid,
        DelegationProxy::{DelegationProxyInstance, implementationCall},
        IERC20::{self, balanceOfCall, decimalsCall},
        IFunder::{self, gasWalletsCall},
    },
};
use alloy::{
    primitives::{ChainId, U256},
    providers::{CallItem, MULTICALL3_ADDRESS, Provider, bindings::IMulticall3::getEthBalanceCall},
    sol_types::SolCall,
};
use eyre::Result;
use itertools::Itertools;
use std::collections::HashSet;
use tokio::try_join;
use tracing::info;

/// Role of an address being checked.
#[derive(Debug, Clone, Copy)]
enum AddressRole {
    Signer,
    FunderContract,
}

/// Diagnostic results for a single chain.
#[derive(Debug)]
pub struct ChainDiagnostics<'a> {
    /// Chain.
    chain: Chain,
    /// Relay configuration.
    config: &'a RelayConfig,
}

impl<'a> ChainDiagnostics<'a> {
    /// Create a new ChainDiagnostics instance
    pub fn new(chain: Chain, config: &'a RelayConfig) -> Self {
        Self { chain, config }
    }

    /// Run all diagnostics.
    pub async fn run(self) -> Result<ChainDiagnosticsResult> {
        let (contract_diagnostics, balance_diagnostics, asset_diagnostics) =
            tokio::try_join!(self.verify_contracts(), self.check_balances(), self.verify_assets())?;

        // Validate interop configuration for this chain
        let interop_config = (self.chain.assets().interop_iter().next().is_some()
            && self.chain.settler_address().is_none())
        .then(|| {
            format!(
                "Chain {} has interop tokens but no settler_address configured",
                self.chain.id()
            )
        });

        Ok(ChainDiagnosticsResult {
            chain_id: self.chain.id(),
            warnings: contract_diagnostics
                .warnings
                .into_iter()
                .chain(balance_diagnostics.warnings)
                .chain(asset_diagnostics.warnings)
                .collect(),
            errors: contract_diagnostics
                .errors
                .into_iter()
                .chain(balance_diagnostics.errors)
                .chain(asset_diagnostics.errors)
                .chain(interop_config)
                .collect(),
        })
    }

    /// Verify contracts are properly deployed and configured.
    ///
    /// Contracts checked:
    /// - Orchestrator, SimpleFunder, Simulator, Escrow: Checks EIP712 domain name matches contract
    ///   type
    /// - Legacy Orchestrators: Same as Orchestrator check
    /// - DelegationProxy (main + legacy): Gets implementation addresses via multicall
    /// - IthacaAccount implementations: Checks EIP712 domain name
    /// - Settler (if configured): Both Simple and LayerZero settlers check EIP712 domain name
    /// - LayerZero configuration: Checked separately in layerzero diagnostics module
    /// - SimpleFunder: Checks all signers are registered as gas wallets and owner key is correct,
    ///   if provided
    async fn verify_contracts(&self) -> Result<ChainDiagnosticsResult> {
        let warnings = Vec::new();
        let mut errors = Vec::new();

        let mut eip712s = vec![
            ("Orchestrator", self.config.orchestrator),
            ("SimpleFunder", self.config.funder),
            ("Simulator", self.config.simulator),
            ("Escrow", self.config.escrow),
        ];

        // Add legacy orchestrators to be checked
        for legacy_orchestrator in &self.config.legacy_orchestrators {
            eip712s.push(("Orchestrator", *legacy_orchestrator));
        }

        // Build multicall to obtain the implementation address of every proxy: main and legacy
        let mut multicall_proxies =
            self.chain.provider().multicall().dynamic::<implementationCall>();
        multicall_proxies = multicall_proxies.add_call_dynamic(
            CallItem::from(
                DelegationProxyInstance::new(self.config.delegation_proxy, &self.chain.provider())
                    .implementation(),
            )
            .allow_failure(true),
        );
        for legacy_delegation_proxy in &self.config.legacy_delegation_proxies {
            multicall_proxies = multicall_proxies.add_call_dynamic(
                CallItem::from(
                    DelegationProxyInstance::new(*legacy_delegation_proxy, &self.chain.provider())
                        .implementation(),
                )
                .allow_failure(true),
            )
        }

        let proxies = std::iter::once(&self.config.delegation_proxy)
            .chain(self.config.legacy_delegation_proxies.iter())
            .map(|address| ("Proxy", *address))
            .collect::<Vec<_>>();

        info!(chain_id = %self.chain.id(), "Fetching proxy implementations");
        crate::process_multicall_results!(
            errors,
            multicall_proxies.aggregate3().await?,
            proxies,
            |implementation, _| eip712s.push(("IthacaAccount", implementation))
        );

        // Add settler to EIP-712 checks
        // Check chain-specific settler if configured
        if let Some(settler_address) = self.chain.settler_address() {
            // Determine settler type from global config
            if let Some(interop) = self.config.interop.as_ref() {
                match &interop.settler.implementation {
                    SettlerImplementation::Simple(_) => {
                        eip712s.push(("SimpleSettler", settler_address));
                    }
                    SettlerImplementation::LayerZero(_) => {
                        eip712s.push(("LayerZeroSettler", settler_address));
                    }
                }
            }
        }

        // Build multicall to call eip712Domain() on all contracts inside eip712s list.
        let mut multicall_eip712 = self.chain.provider().multicall().dynamic::<eip712DomainCall>();
        for (_name, contract) in eip712s.iter() {
            multicall_eip712 = multicall_eip712.add_call_dynamic(
                CallItem::from(IEIP712::new(*contract, &self.chain.provider()).eip712Domain())
                    .allow_failure(true),
            )
        }

        // Build multicall to check gasWallets() mapping for all signers.
        let mut multicall_gas_wallets =
            self.chain.provider().multicall().dynamic::<gasWalletsCall>();
        for address in self.chain.signer_addresses() {
            multicall_gas_wallets = multicall_gas_wallets.add_call_dynamic(
                CallItem::from(
                    IFunder::new(self.config.funder, &self.chain.provider()).gasWallets(address),
                )
                .allow_failure(true),
            );
        }

        info!(chain_id = %self.chain.id(), "Checking EIP712 domains & gas wallets");
        let (eip712_result, gas_wallets_result) = try_join!(
            async { multicall_eip712.aggregate3().await.map_err(eyre::Error::from) },
            async { multicall_gas_wallets.aggregate3().await.map_err(eyre::Error::from) },
        )?;

        crate::process_multicall_results!(
            errors,
            eip712_result,
            eip712s,
            |domain: IEIP712::eip712DomainReturn, (name, contract)| {
                if domain.name != name {
                    errors.push(format!(
                        "got `{}` from {contract}::eip712DomainCall() but expected `{name}`",
                        domain.name
                    ));
                }
            }
        );

        crate::process_multicall_results!(
            errors,
            gas_wallets_result,
            self.chain
                .signer_addresses()
                .map(|addr| (addr, AddressRole::Signer))
                .collect::<Vec<_>>(),
            |is_gas_wallet: bool, (address, _)| {
                if !is_gas_wallet {
                    errors.push(format!(
                        "signer {address} is not registered as a gas wallet in SimpleFunder"
                    ));
                }
            }
        );

        // Ensure that the funder owner key is correct, if configured.
        if let Some(key) = self.config.rebalance_service.as_ref().map(|c| &c.funder_owner_key) {
            let signer = DynSigner::from_raw(key).await?.address();
            let owner =
                IFunder::new(self.config.funder, &self.chain.provider()).owner().call().await?;
            if signer != owner {
                errors.push(format!(
                    "Funder owner key {key} does not match configured funder owner {signer}"
                ));
            }
        }

        Ok(ChainDiagnosticsResult { chain_id: self.chain.id(), warnings, errors })
    }

    /// Check balances for funder contract and the chain's signer addresses.
    ///
    /// Balances checked:
    /// - Native ETH: Funder must have balance (error if 0), signers warned if 0
    /// - Interop tokens: Funder must have balance (error if 0)
    async fn check_balances(&self) -> Result<ChainDiagnosticsResult> {
        let mut errors = Vec::new();

        // Collect all addresses we need to check with their roles
        let mut all_addresses = self
            .chain
            .signer_addresses()
            .map(|signer| (signer, AddressRole::Signer))
            .collect::<Vec<_>>();
        all_addresses.push((self.config.funder, AddressRole::FunderContract));

        // Build multicall to fetch the native balance on all the above addresses
        let mut multicall_native_balance = self.chain.provider().multicall().dynamic();
        for (addr, _) in &all_addresses {
            multicall_native_balance =
                multicall_native_balance.add_call_dynamic(CallItem::<getEthBalanceCall>::new(
                    MULTICALL3_ADDRESS,
                    getEthBalanceCall { addr: *addr }.abi_encode().into(),
                ));
        }

        // Build multicall to fetch the Funder balance of every interop token for this chain.
        let mut multicall_fee_tokens = self.chain.provider().multicall().dynamic::<balanceOfCall>();
        let tokens = self
            .chain
            .assets()
            .interop_iter()
            .filter(|(_, t)| !t.address.is_zero())
            .map(|(_, token)| (token.address, AddressRole::FunderContract))
            .collect::<Vec<_>>();

        for (token, _) in &tokens {
            multicall_fee_tokens = multicall_fee_tokens.add_call_dynamic(
                CallItem::from(
                    IERC20::new(*token, &self.chain.provider()).balanceOf(self.config.funder),
                )
                .allow_failure(true),
            );
        }

        info!(
            chain_id = %self.chain.id(),
            addresses = all_addresses.len(),
            tokens = tokens.len(),
            "Fetching balances"
        );
        let (native_result, fee_tokens_result) =
            try_join!(multicall_native_balance.aggregate3(), multicall_fee_tokens.aggregate3())?;

        crate::process_multicall_results!(errors, native_result, all_addresses, |balance: U256,
                                                                                 (
            account,
            role,
        )| {
            if balance.is_zero() {
                errors.push(format!("[{role:?}] {account} has no native balance"));
            }
        });

        crate::process_multicall_results!(
            errors,
            fee_tokens_result,
            tokens,
            |balance: U256, (token, role)| {
                if balance.is_zero()
                    && let Some((uid, desc)) = self.chain.assets().find_by_address(token)
                {
                    errors.push(format!(
                        "{role:?} has no balance of token {uid} ({}).",
                        desc.address
                    ));
                }
            }
        );

        Ok(ChainDiagnosticsResult { chain_id: self.chain.id(), warnings: vec![], errors })
    }

    /// Verify all assets are accessible, have valid contracts, and config decimals match the
    /// chain's decimals.
    async fn verify_assets(&self) -> Result<ChainDiagnosticsResult> {
        let mut errors = Vec::new();

        let assets: Vec<_> =
            self.chain.assets().iter().filter(|(_, asset)| !asset.address.is_zero()).collect();

        if assets.is_empty() {
            return Ok(ChainDiagnosticsResult {
                chain_id: self.chain.id(),
                warnings: vec![],
                errors,
            });
        }

        // Create a multicall to check decimals for each asset
        let mut multicall = self.chain.provider().multicall().dynamic::<decimalsCall>();
        for (_, asset) in assets.iter() {
            multicall = multicall.add_call_dynamic(
                CallItem::from(IERC20::new(asset.address, &self.chain.provider()).decimals())
                    .allow_failure(true),
            );
        }

        info!(
            chain_id = %self.chain.id(),
            assets = assets.len(),
            "Verifying assets and their decimals"
        );
        crate::process_multicall_results!(
            errors,
            multicall.aggregate3().await?,
            assets,
            |chain_decimals, (uid, config_asset): (_, &AssetDescriptor)| {
                if config_asset.decimals != chain_decimals {
                    errors.push(format!(
                        "Asset {} ({}) has different config decimals ({}) than the chain ({})",
                        uid, config_asset.address, config_asset.decimals, chain_decimals
                    ));
                    return;
                }

                info!(
                    chain_id = %self.chain.id(),
                    asset = %uid,
                    address = %config_asset.address,
                    "Asset verified"
                );
            },
            |asset: &AssetDescriptor| asset.address
        );

        Ok(ChainDiagnosticsResult { chain_id: self.chain.id(), warnings: vec![], errors })
    }
}

/// Result of chain diagnostics run.
#[derive(Debug)]
pub struct ChainDiagnosticsResult {
    /// Chain ID.
    pub chain_id: ChainId,
    /// Warning messages.
    pub warnings: Vec<String>,
    /// Error messages.
    pub errors: Vec<String>,
}

alloy::sol! {
    #[sol(rpc)]
    #[derive(Debug)]
    interface IEIP712 {
        function eip712Domain()
            public
            view
            virtual
            returns (
                bytes1 fields,
                string memory name,
                string memory version,
                uint256 chainId,
                address verifyingContract,
                bytes32 salt,
                uint256[] memory extensions
            );
    }
}

/// Represents connected chains based on shared interop assets.
///
/// Each connection is bidirectional (if A connects to B, then B connects to A).
#[derive(Debug)]
pub struct ConnectedChains {
    /// The tuple pairs are ordered with the smaller chain ID first for consistency.
    connections: HashSet<(ChainId, ChainId)>,
}

impl ConnectedChains {
    /// Create a new instance by finding chain connectivity from the relay configuration.
    pub fn new(config: &RelayConfig) -> Self {
        let mut connections = HashSet::new();

        for (&chain_a, &chain_b) in config.chains.keys().tuple_combinations() {
            let chain_a_id = chain_a.id();
            let chain_b_id = chain_b.id();

            // Collect interop assets from chain A
            let assets_a: HashSet<AssetUid> =
                config.chains[&chain_a].assets.interop_iter().map(|(uid, _)| uid.clone()).collect();

            // Check if chain B has any matching interop assets
            let has_shared_asset = config.chains[&chain_b]
                .assets
                .interop_iter()
                .any(|(uid, _)| assets_a.contains(uid));

            if has_shared_asset {
                // Store the pair (always with smaller chain ID first for consistency)
                let pair = if chain_a_id < chain_b_id {
                    (chain_a_id, chain_b_id)
                } else {
                    (chain_b_id, chain_a_id)
                };
                connections.insert(pair);
            }
        }

        let mut connected_chains = connections.iter().map(|&(chain_a_id, chain_b_id)| {
            let chain_a = alloy_chains::Chain::from(chain_a_id);
            let chain_b = alloy_chains::Chain::from(chain_b_id);

            let a_name =
                chain_a.named().map(|n| n.to_string()).unwrap_or_else(|| chain_a_id.to_string());
            let b_name =
                chain_b.named().map(|n| n.to_string()).unwrap_or_else(|| chain_b_id.to_string());

            format!("{a_name} <-> {b_name}")
        });

        info!(
            "Chain connectivity: {} connections found: [{}]",
            connections.len(),
            connected_chains.join(", ")
        );

        Self { connections }
    }

    /// Iterate over the connections.
    pub fn iter(&self) -> impl Iterator<Item = &(ChainId, ChainId)> {
        self.connections.iter()
    }

    /// Ensures that no mainnet chain is connected to a testnet chain.
    pub fn ensure_no_mainnet_testnet_connections(
        &self,
        errors: &mut Vec<String>,
        warnings: &mut Vec<String>,
    ) {
        for &(chain_a_id, chain_b_id) in &self.connections {
            let chain_a = alloy_chains::Chain::from(chain_a_id);
            let chain_b = alloy_chains::Chain::from(chain_b_id);

            let named_a = chain_a.named();
            let named_b = chain_b.named();

            // If either chain is not a named chain, warn but don't validate
            match (named_a, named_b) {
                (None, _) | (_, None) => {
                    if named_a.is_none() {
                        warnings.push(format!(
                            "Chain {chain_a_id} is not a recognized named chain, skipping mainnet/testnet validation"
                        ));
                    }
                    if named_b.is_none() {
                        warnings.push(format!(
                            "Chain {chain_b_id} is not a recognized named chain, skipping mainnet/testnet validation"
                        ));
                    }
                }
                (Some(named_a), Some(named_b)) => {
                    let a_is_testnet = named_a.is_testnet();
                    let b_is_testnet = named_b.is_testnet();

                    if a_is_testnet != b_is_testnet {
                        errors.push(format!(
                            "Invalid connection between {} chain {} and {} chain {}",
                            if a_is_testnet { "testnet" } else { "mainnet" },
                            named_a,
                            if b_is_testnet { "testnet" } else { "mainnet" },
                            named_b
                        ));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_chains::Chain;

    #[test]
    fn test_mainnet_testnet_validation() {
        let mut connections = HashSet::new();
        connections.insert((Chain::mainnet().id(), Chain::arbitrum_sepolia().id()));

        let mut errors = vec![];
        ConnectedChains { connections }
            .ensure_no_mainnet_testnet_connections(&mut errors, &mut vec![]);

        assert_eq!(errors.len(), 1);
    }
}
