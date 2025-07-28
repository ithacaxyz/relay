use crate::{
    config::{RelayConfig, SettlerImplementation},
    interop::settler::layerzero::{
        ULN_CONFIG_TYPE,
        contracts::{ILayerZeroEndpointV2, UlnConfig},
    },
    signers::DynSigner,
    types::{
        DelegationProxy::DelegationProxyInstance,
        FeeTokens,
        IERC20::{self},
        IFunder,
    },
};
use alloy::{
    primitives::{Address, Bytes, U256, utils::format_ether},
    providers::{CallItem, MULTICALL3_ADDRESS, Provider, bindings::IMulticall3::getEthBalanceCall},
    sol_types::{SolCall, SolType},
};
use eyre::Result;
use futures_util::future::join_all;
use tokio::try_join;

/// Role of an address being checked.
#[derive(Debug, Clone, Copy)]
enum AddressRole {
    Signer,
    FunderContract,
}

/// Diagnostic results for a single chain.
#[derive(Debug)]
pub struct ChainDiagnostics<'a, P: Provider> {
    /// Provider.
    provider: P,
    /// Chain ID.
    chain_id: u64,
    /// Relay configuration.
    config: &'a RelayConfig,
}

/// Result of chain diagnostics run.
#[derive(Debug)]
pub struct ChainDiagnosticsResult {
    /// Chain ID.
    pub chain_id: u64,
    /// Warning messages.
    pub warnings: Vec<String>,
    /// Error messages.
    pub errors: Vec<String>,
}

impl<'a, P: Provider> ChainDiagnostics<'a, P> {
    /// Create a new ChainDiagnostics instance
    pub fn new(provider: P, chain_id: u64, config: &'a RelayConfig) -> Self {
        Self { provider, chain_id, config }
    }

    /// Run all diagnostics.
    pub async fn run(
        self,
        fee_tokens: &FeeTokens,
        signers: &[DynSigner],
    ) -> Result<ChainDiagnosticsResult> {
        let (contract_diagnostics, balance_diagnostics) =
            try_join!(self.verify_contracts(signers), self.check_balances(fee_tokens, signers))?;

        Ok(ChainDiagnosticsResult {
            chain_id: self.chain_id,
            warnings: contract_diagnostics
                .warnings
                .into_iter()
                .chain(balance_diagnostics.warnings)
                .collect(),
            errors: contract_diagnostics
                .errors
                .into_iter()
                .chain(balance_diagnostics.errors)
                .collect(),
        })
    }

    /// Check if contracts have code deployed otherwise return error messages.
    async fn check_contracts_have_code(
        &self,
        contracts: impl IntoIterator<Item = (&str, Address)>,
    ) -> Result<Vec<String>> {
        let errors = join_all(contracts.into_iter().map(async |(label, address)| {
            let Ok(code) = self.provider.get_code_at(address).await else {
                return Some(format!("{label} {address}: provider error"));
            };

            if code.is_empty() {
                Some(format!("{label} {address} has no code deployed"))
            } else {
                None
            }
        }))
        .await
        .into_iter()
        .flatten()
        .collect();

        Ok(errors)
    }

    /// Verify contracts are properly deployed and configured.
    ///
    /// Contracts checked:
    /// - Simulator, Escrow: Only checks if code is deployed
    /// - Orchestrator, SimpleFunder: Checks code + EIP712 domain name matches contract type
    /// - Legacy Orchestrators: Same as Orchestrator check
    /// - DelegationProxy (main + legacy): Gets implementation addresses via multicall
    /// - IthacaAccount implementations: Checks code + EIP712 domain name
    /// - Settler (if configured): Simple settler checks EIP712, LayerZero settler only checks code
    /// - LayerZero configuration (if applicable): Validates ULN config for each remote chain
    /// - SimpleFunder: Checks all signers are registered as gas wallets and owner key is correct,
    ///   if provided
    pub async fn verify_contracts(&self, signers: &[DynSigner]) -> Result<ChainDiagnosticsResult> {
        let mut warnings = Vec::new();
        let mut errors = Vec::new();

        // todo(joshie): once all contracts implement eip712/version+name, check_code_exists can go
        // away
        let mut check_code_exists =
            vec![("Simulator", self.config.simulator), ("Escrow", self.config.escrow)];
        let mut eip712s =
            vec![("Orchestrator", self.config.orchestrator), ("SimpleFunder", self.config.funder)];

        // Add legacy orchestrators to be checked
        for legacy_orchestrator in &self.config.legacy_orchestrators {
            eip712s.push(("Orchestrator", *legacy_orchestrator));
        }

        // Build multicall to obtain the implementation address of every proxy: main and legacy
        let mut multicall_proxies = self.provider.multicall().dynamic().add_dynamic(
            DelegationProxyInstance::new(self.config.delegation_proxy, &self.provider)
                .implementation(),
        );
        for legacy_delegation_proxy in &self.config.legacy_delegation_proxies {
            multicall_proxies = multicall_proxies.add_dynamic(
                DelegationProxyInstance::new(*legacy_delegation_proxy, &self.provider)
                    .implementation(),
            )
        }

        let proxies = std::iter::once(&self.config.delegation_proxy)
            .chain(self.config.legacy_delegation_proxies.iter())
            .map(|address| ("Proxy", *address))
            .collect::<Vec<_>>();

        crate::process_multicall_results!(
            errors,
            multicall_proxies.aggregate3().await?,
            proxies,
            |implementation, _| eip712s.push(("IthacaAccount", implementation))
        );

        // Only SimpleSettler implements eip712 for now.
        if let Some(settler) = self.config.interop.as_ref().map(|i| &i.settler.implementation) {
            if let SettlerImplementation::Simple(_) = settler {
                eip712s.push(("SimpleSettler", settler.address()));
            } else {
                check_code_exists.push(("LayerZeroSettler", settler.address()));
            }
        }

        // Build multicall to call eip712Domain() on all contracts inside eip712s list.
        let mut multicall_eip712 = self.provider.multicall().dynamic();
        for (_name, contract) in eip712s.iter() {
            multicall_eip712 =
                multicall_eip712.add_dynamic(IEIP712::new(*contract, &self.provider).eip712Domain())
        }

        // Build multicall to check gasWallets() mapping for all signers.
        let mut multicall_gas_wallets = self.provider.multicall().dynamic();
        let gas_wallets = signers.iter().map(|s| (s.address(), ())).collect::<Vec<_>>();
        for (address, _) in &gas_wallets {
            multicall_gas_wallets = multicall_gas_wallets
                .add_dynamic(IFunder::new(self.config.funder, &self.provider).gasWallets(*address));
        }

        let (eip712_result, gas_wallets_result, has_code_errors, lz_result) = try_join!(
            async { multicall_eip712.aggregate3().await.map_err(eyre::Error::from) },
            async { multicall_gas_wallets.aggregate3().await.map_err(eyre::Error::from) },
            self.check_contracts_have_code(check_code_exists),
            self.maybe_check_layerzero(),
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
            gas_wallets,
            |is_gas_wallet: bool, (address, _)| {
                if !is_gas_wallet {
                    errors.push(format!(
                        "signer {address} is not registered as a gas wallet in SimpleFunder"
                    ));
                }
            }
        );

        // Ensure that the funder owner key is correct, if configured.
        if let Some(key) = self.config.chain.rebalance_service.as_ref().map(|c| &c.funder_owner_key)
        {
            let signer = DynSigner::from_raw(key).await?.address();
            let owner = IFunder::new(self.config.funder, &self.provider).owner().call().await?;
            if signer != owner {
                errors.push(format!(
                    "Funder owner key {key} does not match configured funder owner {signer}"
                ));
            }
        }

        warnings.extend(lz_result.warnings);
        errors.extend(lz_result.errors);
        errors.extend(has_code_errors);

        Ok(ChainDiagnosticsResult { chain_id: self.chain_id, warnings, errors })
    }

    /// Check balances for funder contract and signer addresses.
    ///
    /// Balances checked:
    /// - Native ETH: Funder must have balance (error if 0), signers warned if 0
    /// - Interop tokens: Funder must have balance (error if 0)
    pub async fn check_balances(
        &self,
        fee_tokens: &FeeTokens,
        signers: &[DynSigner],
    ) -> Result<ChainDiagnosticsResult> {
        let mut warnings = Vec::new();
        let mut errors = Vec::new();

        // Ensure we only have a single interop-enabled token of each kind
        let interop_kinds = fee_tokens
            .chain_tokens(self.chain_id)
            .iter()
            .flat_map(|t| t.iter())
            .filter(|t| t.interop)
            .map(|t| t.kind)
            .collect::<Vec<_>>();

        for kind in &interop_kinds {
            if interop_kinds.iter().filter(|k| *k == kind).count() > 1 {
                errors.push(format!("Multiple interop-enabled tokens of kind {kind} found"));
            }
        }

        // Collect all addresses we need to check with their roles
        let mut all_addresses = signers
            .iter()
            .map(|signer| (signer.address(), AddressRole::Signer))
            .collect::<Vec<_>>();
        all_addresses.push((self.config.funder, AddressRole::FunderContract));

        // Build multicall to fetch the native balance on all the above addresses
        let mut multicall_native_balance = self.provider.multicall().dynamic();
        for (addr, _) in &all_addresses {
            multicall_native_balance =
                multicall_native_balance.add_call_dynamic(CallItem::<getEthBalanceCall>::new(
                    MULTICALL3_ADDRESS,
                    getEthBalanceCall { addr: *addr }.abi_encode().into(),
                ));
        }

        // Build multicall to fetch the Funder balance of every token valid for this chain.
        let mut multicall_fee_tokens = self.provider.multicall().dynamic();
        let tokens = fee_tokens
            .chain_tokens(self.chain_id)
            .iter()
            .flat_map(|t| t.iter())
            .map(|token| (token.address, AddressRole::FunderContract))
            .collect::<Vec<_>>();

        for (token, _) in &tokens {
            multicall_fee_tokens = multicall_fee_tokens
                .add_dynamic(IERC20::new(*token, &self.provider).balanceOf(self.config.funder));
        }

        let (native_result, fee_tokens_result) =
            try_join!(multicall_native_balance.aggregate3(), multicall_fee_tokens.aggregate3())?;

        crate::process_multicall_results!(errors, native_result, all_addresses, |balance: U256,
                                                                                 (
            account,
            role,
        )| {
            match role {
                AddressRole::Signer => {
                    if balance.is_zero() {
                        warnings.push(format!(
                            "Signer {account} has low balance: {} ETH",
                            format_ether(balance)
                        ));
                    }
                }
                AddressRole::FunderContract => {
                    if balance.is_zero() {
                        errors.push(format!("Funder contract {account} has no balance",));
                    }
                }
            }
        });

        crate::process_multicall_results!(
            errors,
            fee_tokens_result,
            tokens,
            |balance: U256, (token, role)| {
                if balance.is_zero() && self.config.chain.interop_tokens.contains(&token) {
                    errors.push(format!("{role:?} has no balance on {token}.",));
                }
            }
        );

        Ok(ChainDiagnosticsResult { chain_id: self.chain_id, warnings, errors })
    }

    /// Checks the LayerZero settler configuration on chain.
    ///
    /// Checks performed:
    /// - Endpoint address and endpoint ID configured for current chain
    /// - Fetches receive library for each remote chain
    /// - Validates number of configured remote chains matches expected
    /// - For each remote chain's ULN config:
    ///   - Config exists and can be decoded
    ///   - Has confirmations > 0 (warning if 0)
    ///   - Has at least one DVN configured (error if none)
    ///   - DVN count matches array length
    ///   - No zero addresses in DVN list
    async fn maybe_check_layerzero(&self) -> Result<ChainDiagnosticsResult> {
        let mut report = ChainDiagnosticsResult {
            chain_id: self.chain_id,
            warnings: Vec::new(),
            errors: Vec::new(),
        };

        // Check if LayerZero is configured
        let Some(interop) = &self.config.interop else {
            return Ok(report);
        };

        let SettlerImplementation::LayerZero(lz_config) = &interop.settler.implementation else {
            return Ok(report);
        };

        // Ensure there is an endpoint address for this chain
        let Some(endpoint_address) = lz_config.endpoint_addresses.get(&self.chain_id).copied()
        else {
            report
                .errors
                .push(format!("No LayerZero endpoint configured for chain {}", self.chain_id));
            return Ok(report);
        };

        // Ensure there is an endpoint id for this chain
        let Some(_local_eid) = lz_config.endpoint_ids.get(&self.chain_id).copied() else {
            report
                .errors
                .push(format!("No LayerZero endpoint ID configured for chain {}", self.chain_id));
            return Ok(report);
        };

        let endpoint = ILayerZeroEndpointV2::new(endpoint_address, &self.provider);

        // Build multicall to fetch the receive library for all other remote chains.
        let mut multicall_get_lib = self.provider.multicall().dynamic();
        let mut remote_chains = Vec::new();

        for (remote_chain_id, remote_eid) in &lz_config.endpoint_ids {
            // Skip checking against ourselves
            if *remote_chain_id == self.chain_id {
                continue;
            }
            multicall_get_lib = multicall_get_lib
                .add_dynamic(endpoint.getReceiveLibrary(lz_config.settler_address, *remote_eid));
            remote_chains.push((*remote_chain_id, *remote_eid));
        }

        if remote_chains.len() != self.config.chain.endpoints.len() - 1 {
            report.errors.push(format!(
                "LayerZeroSettler@{} on chain {} only has {} chains configured instead of {}.",
                lz_config.settler_address,
                self.chain_id,
                remote_chains.len(),
                self.config.chain.endpoints.len() - 1
            ));
        }

        // Process library results and build config multicall
        let mut valid_remote_chains = Vec::with_capacity(remote_chains.len());
        crate::process_multicall_results!(
            report.errors,
            multicall_get_lib.aggregate3().await?,
            remote_chains.clone(),
            |lib_info: ILayerZeroEndpointV2::getReceiveLibraryReturn,
             (remote_chain_id, remote_eid)| {
                valid_remote_chains.push((lib_info.lib, (remote_chain_id, remote_eid)));
            }
        );

        // Build multicall to fetch the receive configuration for all other remote chains.
        let mut multicall_get_config = self.provider.multicall().dynamic();
        for (lib, (_, remote_eid)) in &valid_remote_chains {
            multicall_get_config = multicall_get_config.add_dynamic(endpoint.getConfig(
                lz_config.settler_address,
                *lib,
                *remote_eid,
                ULN_CONFIG_TYPE,
            ));
        }

        // Ensure there is a valid configuration for every remote chain.
        if !valid_remote_chains.is_empty() {
            crate::process_multicall_results!(
                report.errors,
                multicall_get_config.aggregate3().await?,
                valid_remote_chains,
                |config_bytes: Bytes, (_, (remote_chain_id, remote_eid))| {
                    // Decode and validate the ULN configuration
                    let Ok(uln_config) = UlnConfig::abi_decode(&config_bytes) else {
                        report.errors.push(format!(
                            "Failed to decode LayerZero ULN configuration for remote chain {remote_chain_id} (EID {remote_eid})"
                        ));
                        return;
                    };

                    // Validate the configuration
                    if uln_config.confirmations == 0 {
                        report.warnings.push(format!(
                            "LayerZero ULN config has 0 confirmations for remote chain {remote_chain_id} (EID {remote_eid})"
                        ));
                    }

                    if uln_config.requiredDVNCount == 0 && uln_config.optionalDVNCount == 0 {
                        report.errors.push(format!(
                            "LayerZero ULN config has no DVNs configured for remote chain {remote_chain_id} (EID {remote_eid})"
                        ));
                    }

                    if uln_config.requiredDVNs.len() != uln_config.requiredDVNCount as usize {
                        report.errors.push(format!(
                            "LayerZero ULN config DVN count mismatch: expected {} required DVNs but found {} for remote chain {} (EID {})",
                            uln_config.requiredDVNCount,
                            uln_config.requiredDVNs.len(),
                            remote_chain_id,
                            remote_eid
                        ));
                    }

                    // Check for zero addresses in DVNs
                    for (i, dvn) in uln_config.requiredDVNs.iter().enumerate() {
                        if dvn.is_zero() {
                            report.errors.push(format!(
                                "LayerZero ULN config has zero address for required DVN {i} for remote chain {remote_chain_id} (EID {remote_eid})"
                            ));
                        }
                    }
                }
            );
        }

        Ok(report)
    }
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
