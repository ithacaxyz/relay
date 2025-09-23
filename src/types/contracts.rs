use crate::{
    config::RelayConfig, error::RelayError, types::DelegationProxy::DelegationProxyInstance,
};
use alloy::{
    dyn_abi::Eip712Domain, primitives::Address, providers::Provider, sol,
    transports::TransportErrorKind,
};
use eyre::eyre;
use futures_util::future::try_join_all;
use semver::Version;
use serde::{Deserialize, Serialize};
use tokio::try_join;

sol! {
    #[sol(rpc)]
    interface Eip712Contract {
        /// Returns the EIP712 domain of the delegation.
        ///
        /// See: https://eips.ethereum.org/EIPS/eip-5267
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

/// Contract address with optional version.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionedContract {
    /// Contract address.
    pub address: Address,
    /// Contract version.
    #[serde(default)]
    pub version: Option<Version>,
    /// Cached EIP712 Domain.
    #[serde(skip)]
    pub domain: Option<Eip712Domain>,
}

impl VersionedContract {
    /// Creates a [`VersionedContract`].
    ///
    /// This fetches the contract version and domain by calling `eip712Domain()` on the contract.
    pub async fn new<P: Provider>(address: Address, provider: P) -> Result<Self, RelayError> {
        let domain_data = Eip712Contract::new(address, provider).eip712Domain().call().await?;

        tracing::debug!(
            name = %domain_data.name,
            contract = %address,
            version = %domain_data.version,
            chain_id = %domain_data.chainId,
            "Fetched EIP712 domain"
        );

        let version = Version::parse(&domain_data.version).map_err(|e| {
            RelayError::InternalError(eyre!(
                "Failed to parse version '{}' as semver: {}",
                domain_data.version,
                e
            ))
        })?;

        let domain = Some(Eip712Domain::new(
            Some(domain_data.name.into()),
            Some(domain_data.version.into()),
            Some(domain_data.chainId),
            Some(domain_data.verifyingContract),
            None,
        ));

        Ok(Self { address, version: Some(version), domain })
    }

    /// Gets the cached EIP712 domain.
    ///
    /// If `multichain` is `true`, returns the domain without chain ID.
    ///
    /// # Panics
    ///
    /// Panics if the domain was not successfully fetched during construction.
    pub fn eip712_domain(&self, multichain: bool) -> Eip712Domain {
        let d = self
            .domain
            .as_ref()
            .expect("EIP712 domain should have been cached during construction");

        let mut domain = d.clone();
        if multichain {
            domain.chain_id = None;
        }
        domain
    }

    /// Creates a [`VersionedContract`] without a version.
    pub fn no_version(address: Address) -> Self {
        Self { address, version: None, domain: None }
    }
}

/// Relay versioned contracts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionedContracts {
    /// Latest orchestrator.
    pub orchestrator: VersionedContract,
    /// The delegation implementation.
    ///
    /// This is directly fetched from the proxy.
    #[serde(rename = "accountImplementation")]
    pub delegation_implementation: VersionedContract,
    /// Previously deployed orchestrators and simulators.
    pub legacy_orchestrators: Vec<VersionedOrchestratorContracts>,
    /// Previously deployed delegation implementations.
    #[serde(rename = "legacyAccountImplementations")]
    pub legacy_delegations: Vec<VersionedContract>,
    /// Delegation proxy.
    #[serde(rename = "accountProxy")]
    pub delegation_proxy: VersionedContract,
    /// Simulator.
    pub simulator: VersionedContract,
    /// Funder.
    pub funder: VersionedContract,
    /// Escrow.
    pub escrow: VersionedContract,
}

impl VersionedContracts {
    /// Generates a [`VersionedContracts`] from [`RelayConfig`].
    pub async fn new<P: Provider>(config: &RelayConfig, provider: &P) -> Result<Self, RelayError> {
        let legacy_orchestrators =
            try_join_all(config.legacy_orchestrators.iter().map(async |&legacy| {
                tracing::debug!(
                    orchestrator = %legacy.orchestrator,
                    "Creating VersionedContract for legacy orchestrator"
                );
                let orchestrator = VersionedContract::new(legacy.orchestrator, provider).await?;
                tracing::debug!(
                    simulator = %legacy.simulator,
                    "Creating VersionedContract for legacy simulator"
                );
                let simulator = VersionedContract::new(legacy.simulator, provider).await?;
                Ok::<_, RelayError>(VersionedOrchestratorContracts { orchestrator, simulator })
            }));

        let legacy_delegations =
            try_join_all(config.legacy_delegation_proxies.iter().map(async |&proxy_address| {
                let implementation = DelegationProxyInstance::new(proxy_address, provider)
                    .implementation()
                    .call()
                    .await
                    .map_err(TransportErrorKind::custom)?;

                VersionedContract::new(implementation, provider).await
            }));

        let orchestrator = async {
            tracing::debug!(
                orchestrator = %config.orchestrator,
                "Creating VersionedContract for current orchestrator"
            );
            VersionedContract::new(config.orchestrator, provider).await
        };

        let delegation_implementation = async {
            let delegation_implementation =
                DelegationProxyInstance::new(config.delegation_proxy, provider)
                    .implementation()
                    .call()
                    .await
                    .map_err(TransportErrorKind::custom)?;

            VersionedContract::new(delegation_implementation, provider).await
        };

        let (legacy_orchestrators, legacy_delegations, orchestrator, delegation_implementation) = try_join!(
            legacy_orchestrators,
            legacy_delegations,
            orchestrator,
            delegation_implementation
        )?;

        Ok(Self {
            orchestrator,
            delegation_implementation,
            legacy_orchestrators,
            legacy_delegations,
            delegation_proxy: VersionedContract::no_version(config.delegation_proxy),
            simulator: VersionedContract::no_version(config.simulator),
            funder: VersionedContract::no_version(config.funder),
            escrow: VersionedContract::no_version(config.escrow),
        })
    }

    /// The latest orchestrator address.
    pub fn orchestrator(&self) -> Address {
        self.orchestrator.address
    }

    /// Get previously deployed orchestrator and simulator by orchestrator address.
    pub fn get_legacy_orchestrator(
        &self,
        address: Address,
    ) -> Option<&VersionedOrchestratorContracts> {
        self.legacy_orchestrators.iter().find(|c| c.orchestrator.address == address)
    }

    /// Returns the matching simulator for the orchestrator (current or legacy).
    pub fn get_simulator_for_orchestrator(&self, orchestrator_address: Address) -> Address {
        if orchestrator_address == self.orchestrator() {
            // Current orchestrator uses current simulator
            self.simulator()
        } else if let Some(legacy) = self.get_legacy_orchestrator(orchestrator_address) {
            // Legacy orchestrator uses its corresponding simulator
            legacy.simulator.address
        } else {
            // Fallback to current simulator if orchestrator not found
            self.simulator()
        }
    }

    /// Previously deployed delegation implementations.
    pub fn legacy_delegations(&self) -> impl Iterator<Item = Address> + '_ {
        self.legacy_delegations.iter().map(|c| c.address)
    }

    /// The delegation proxy address.
    pub fn delegation_proxy(&self) -> Address {
        self.delegation_proxy.address
    }

    /// The delegation implementation address.
    pub fn delegation_implementation(&self) -> Address {
        self.delegation_implementation.address
    }

    /// The simulator address.
    pub fn simulator(&self) -> Address {
        self.simulator.address
    }

    /// The escrow address.
    pub fn escrow(&self) -> Address {
        self.escrow.address
    }

    /// The funder address.
    pub fn funder(&self) -> Address {
        self.funder.address
    }

    /// Gets the version of a delegation implementation.
    ///
    /// Returns None if the address is not a known delegation implementation.
    pub fn get_delegation_implementation_version(
        &self,
        impl_addr: Address,
    ) -> Option<semver::Version> {
        if impl_addr == self.delegation_implementation.address {
            return self.delegation_implementation.version.clone();
        }

        // Check legacy implementations
        self.legacy_delegations
            .iter()
            .find_map(|c| (c.address == impl_addr).then_some(c.version.clone()))
            .flatten()
    }

    /// Get versioned orchestrator by address.
    pub fn get_versioned_orchestrator(
        &self,
        address: Address,
    ) -> Result<&VersionedContract, RelayError> {
        if self.orchestrator() == address {
            tracing::trace!(
                orchestrator = %address,
                version = ?self.orchestrator.version,
                "Using current orchestrator"
            );
            Ok(&self.orchestrator)
        } else if let Some(legacy) = self.get_legacy_orchestrator(address) {
            tracing::trace!(
                orchestrator = %address,
                version = ?legacy.orchestrator.version,
                "Using legacy orchestrator"
            );
            Ok(&legacy.orchestrator)
        } else {
            Err(RelayError::UnsupportedOrchestrator(address))
        }
    }
}

/// Orchestrator and simulator versioned contracts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionedOrchestratorContracts {
    /// Orchestrator contract.
    pub orchestrator: VersionedContract,
    /// Simulator contract.
    pub simulator: VersionedContract,
}
