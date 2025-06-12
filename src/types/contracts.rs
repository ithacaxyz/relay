use crate::{
    config::RelayConfig,
    error::RelayError,
    types::{Account, DelegationProxy::DelegationProxyInstance, Orchestrator},
};
use alloy::{primitives::Address, providers::Provider, transports::TransportErrorKind};
use futures_util::future::try_join_all;
use serde::{Deserialize, Serialize};
use tokio::try_join;

/// Contract address with optional version.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct VersionedContract {
    /// Contract address.
    pub address: Address,
    /// Contract version.
    #[serde(default)]
    pub version: Option<String>,
}

impl VersionedContract {
    /// Creates a [`VersionedContract`].
    pub fn new(address: Address, version: String) -> Self {
        Self { address, version: Some(version) }
    }

    /// Creates a [`VersionedContract`] without a version.
    pub fn no_version(address: Address) -> Self {
        Self { address, version: None }
    }
}

/// Relay versioned contracts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionedContracts {
    /// Orchestrator.
    pub orchestrator: VersionedContract,
    /// The delegation implementation.
    ///
    /// This is directly fetched from the proxy.
    #[serde(rename = "accountImplementation")]
    pub delegation_implementation: VersionedContract,
    /// Previously deployed orchestrators.
    pub legacy_orchestrators: Vec<VersionedContract>,
    /// Previously deployed delegation implementations.
    #[serde(rename = "legacyAccountImplementations")]
    pub legacy_delegations: Vec<VersionedContract>,
    /// Delegation proxy.
    #[serde(rename = "accountProxy")]
    pub delegation_proxy: VersionedContract,
    /// Simulator.
    pub simulator: VersionedContract,
}

impl VersionedContracts {
    /// Generates a [`VersionedContracts`] from [`RelayConfig`].
    pub async fn new<P: Provider>(config: &RelayConfig, provider: &P) -> Result<Self, RelayError> {
        let legacy_orchestrators =
            try_join_all(config.legacy_orchestrators.iter().map(async |&address| {
                Ok::<_, RelayError>(VersionedContract::new(
                    address,
                    Orchestrator::new(address, provider).version().await?,
                ))
            }));

        let legacy_delegations =
            try_join_all(config.legacy_delegation_proxies.iter().map(async |&proxy_address| {
                let implementation = DelegationProxyInstance::new(proxy_address, provider)
                    .implementation()
                    .call()
                    .await
                    .map_err(TransportErrorKind::custom)?;

                Ok(VersionedContract::new(
                    implementation,
                    Account::new(implementation, provider).version().await?,
                ))
            }));

        let orchestrator = async {
            Ok(VersionedContract::new(
                config.orchestrator,
                Orchestrator::new(config.orchestrator, provider).version().await?,
            ))
        };

        let delegation_implementation = async {
            let delegation_implementation =
                DelegationProxyInstance::new(config.delegation_proxy, provider)
                    .implementation()
                    .call()
                    .await
                    .map_err(TransportErrorKind::custom)?;

            Ok(VersionedContract::new(
                delegation_implementation,
                Account::new(delegation_implementation, provider).version().await?,
            ))
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
        })
    }
}
